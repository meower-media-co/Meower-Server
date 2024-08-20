package packets

import "github.com/meower-media-co/server/pkg/api/events/models"

type V0PostReactionAdd struct {
	ChatId   string         `json:"chat_id" msgpack:"chat_id"`
	PostId   string         `json:"post_id" msgpack:"post_id"`
	Emoji    string         `json:"emoji" msgpack:"emoji"`
	User     *models.V0User `json:"user" msgpack:"user"`
	Username string         `json:"username" msgpack:"username"`
}

type V1PostReactionAdd = V0PostReactionAdd
