package notify

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pocketsentry/pocketsentry/internal/helpers"
	"github.com/pocketsentry/pocketsentry/internal/models"
)

// Global webhook credentials (set from CLI flags in main).
var (
	DiscordWebhookURL string
	TgToken           string
	TgChatID          string
)

// DB is the shared database connection, set from main.
var DB *sql.DB

// ---------- Telegram Bot Polling ----------

var (
	activePollers = make(map[string]bool)
	pollerMutex   sync.Mutex
)

// EnsureTelegramPollers periodically checks for new bot tokens and starts pollers.
func EnsureTelegramPollers() {
	for {
		tokens := make(map[string]bool)
		if TgToken != "" {
			tokens[TgToken] = true
		}

		rows, err := DB.Query("SELECT DISTINCT tg_token FROM projects WHERE tg_token IS NOT NULL AND tg_token != ''")
		if err == nil {
			for rows.Next() {
				var t string
				if err := rows.Scan(&t); err == nil {
					tokens[t] = true
				}
			}
			rows.Close()
		}

		pollerMutex.Lock()
		for t := range tokens {
			if !activePollers[t] {
				activePollers[t] = true
				go runTelegramPoller(t)
			}
		}
		pollerMutex.Unlock()

		time.Sleep(1 * time.Minute)
	}
}

func runTelegramPoller(token string) {
	offset := 0
	log.Printf("[telegram] started polling for bot token: %s...", token[:5])

	for {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", token, offset)
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		var updateRes struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID      int `json:"update_id"`
				CallbackQuery struct {
					ID      string `json:"id"`
					Message struct {
						MessageID int `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
						Text string `json:"text"`
					} `json:"message"`
					Data string `json:"data"`
					From struct {
						FirstName string `json:"first_name"`
					} `json:"from"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		err = json.NewDecoder(resp.Body).Decode(&updateRes)
		resp.Body.Close()
		if err != nil || !updateRes.Ok {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, u := range updateRes.Result {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}

			cb := u.CallbackQuery
			if strings.HasPrefix(cb.Data, "resolve_") {
				eventID := strings.TrimPrefix(cb.Data, "resolve_")

				// Resolve event in DB
				_, _ = DB.Exec("UPDATE events SET status = 'resolved' WHERE id = ?", eventID)

				// Answer callback (removes loading state from button)
				ansURL := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery?callback_query_id=%s&text=Event%%20Resolved!", token, cb.ID)
				_, _ = http.Get(ansURL)

				// Edit message to remove button and append resolved info
				newText := cb.Message.Text + fmt.Sprintf("\n\n✅ *Resolved by %s*", cb.From.FirstName)
				editURL := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", token)

				payload, _ := json.Marshal(map[string]interface{}{
					"chat_id":    cb.Message.Chat.ID,
					"message_id": cb.Message.MessageID,
					"text":       newText,
				})
				http.Post(editURL, "application/json", bytes.NewReader(payload))
			}
		}
	}
}

// ---------- Webhooks ----------

// EvaluateAndTriggerWebhooks evaluates smart alerting rules before triggering.
// If any rule matches, it sends to the rule's specific targets. If no rule matches,
// it falls back to the default project/global webhooks ONLY IF shouldNotify is true
// (which means it's a new or reopened event).
func EvaluateAndTriggerWebhooks(ev models.SentryEvent, projectID string, shouldNotify bool) {
	// First, fetch all enabled alerting rules for this project.
	rows, err := DB.Query("SELECT environment, min_count, time_window_minutes, target_discord, target_telegram_token, target_telegram_chat_id FROM alerting_rules WHERE project_id = ? AND enabled = 1", projectID)
	if err == nil {
		defer rows.Close()
		var env string
		var minCount, timeWindow int
		var tDiscord, tTGToken, tTGChatID string

		ruleMatched := false

		for rows.Next() {
			if err := rows.Scan(&env, &minCount, &timeWindow, &tDiscord, &tTGToken, &tTGChatID); err != nil {
				continue
			}

			// Check environment match
			if env != "" && ev.Environment != env && ev.Environment != "" {
				continue
			}

			// Check rate limit threshold
			countMatched := true
			if minCount > 1 && timeWindow > 0 {
				var currentCount int
				err := DB.QueryRow("SELECT count FROM events WHERE project_id = ? AND message = ? AND level = ?", projectID, ev.Message, ev.Level).Scan(&currentCount)
				if err != nil || currentCount < minCount || currentCount%minCount != 0 {
					countMatched = false
				}
			}

			if countMatched {
				// We found a matching rule! Trigger its specific webhooks.
				ruleMatched = true
				msg := fmt.Sprintf("🚨 **PocketSentry Smart Alert**\n\n**Project:** %s\n**Level:** %s\n**Message:** %s\n**Time:** %s",
					projectID, ev.Level, helpers.Truncate(ev.Message, 150), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

				if tDiscord != "" {
					go SendDiscordWebhook(tDiscord, msg)
				}
				if tTGToken != "" && tTGChatID != "" {
					go SendTelegramWebhook(tTGToken, tTGChatID, msg, ev.EventID)
				}
			}
		}

		if ruleMatched {
			// If a specific rule fired, we don't fire the default fallback.
			return
		}
	}

	// No rules matched. Fallback to default if shouldNotify is true.
	if shouldNotify {
		TriggerWebhooks(ev, projectID)
	}
}

// TriggerWebhooks sends a notification to configured default webhooks.
func TriggerWebhooks(ev models.SentryEvent, projectID string) {
	// Format the message
	msg := fmt.Sprintf("🚨 **PocketSentry Alert**\n\n**Project:** %s\n**Level:** %s\n**Message:** %s\n**Time:** %s",
		projectID, ev.Level, helpers.Truncate(ev.Message, 150), time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	// Default webhook targets
	targetDiscord := DiscordWebhookURL
	targetTGToken := TgToken
	targetTGChatID := TgChatID

	// Check if this project has webhook overrides
	var pTGToken, pTGChatID, pDiscordWebhook string
	err := DB.QueryRow("SELECT COALESCE(tg_token, ''), COALESCE(tg_chat_id, ''), COALESCE(discord_webhook, '') FROM projects WHERE id = ?", projectID).Scan(&pTGToken, &pTGChatID, &pDiscordWebhook)
	if err == nil {
		if pDiscordWebhook != "" {
			targetDiscord = pDiscordWebhook
		}
		if pTGToken != "" && pTGChatID != "" {
			targetTGToken = pTGToken
			targetTGChatID = pTGChatID
		}
	}

	// Discord
	if targetDiscord != "" {
		go SendDiscordWebhook(targetDiscord, msg)
	}

	// Telegram
	if targetTGToken != "" && targetTGChatID != "" {
		go SendTelegramWebhook(targetTGToken, targetTGChatID, msg, ev.EventID)
	}
}

// SendDiscordWebhook sends a message to a Discord webhook URL.
func SendDiscordWebhook(url, content string) {
	payload, _ := json.Marshal(map[string]string{"content": content})
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[discord] webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[discord] webhook returned status %d", resp.StatusCode)
	}
}

// SendTelegramWebhook sends a message to a Telegram chat via Bot API.
func SendTelegramWebhook(token, chatID, content, eventID string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payloadData := map[string]interface{}{
		"chat_id":    chatID,
		"text":       content,
		"parse_mode": "Markdown",
	}

	if eventID != "" {
		payloadData["reply_markup"] = map[string]interface{}{
			"inline_keyboard": [][]map[string]interface{}{
				{
					{
						"text":          "✅ Resolve",
						"callback_data": "resolve_" + eventID,
					},
				},
			},
		}
	}

	payload, _ := json.Marshal(payloadData)
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[telegram] webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("[telegram] webhook returned status %d", resp.StatusCode)
	}
}
