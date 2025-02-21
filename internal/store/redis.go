package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type Store struct {
	client *redis.Client
}

func NewStore() *Store {
	return &Store{
		client: redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "",
			DB:       0,
		}),
	}
}

type StoreAuthCodeValue struct {
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
}

type TokenValue struct {
	ClientID     string    `bson:"client_id"`
	AccessToken  string    `bson:"access_token"`
	IssuedAt     time.Time `bson:"issued_at"`
	ExpiresIn    int       `bson:"expires_in"`
	RefreshToken string    `bson:"refresh_token"`
	TokenType    string    `bson:"token_type"`
}

func NewStoreAuthCodeValue(userID, clientID, redirectURI, state string) StoreAuthCodeValue {
	return StoreAuthCodeValue{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		State:       state,
	}
}

func (s *Store) Close() {
	s.client.Close()
}

func (s *Store) Ping() error {
	return s.client.Ping(context.Background()).Err()
}

func (s *Store) Set(ctx context.Context, code string, v any, t time.Duration) error {
	d, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, code, d, t).Err()
}

func (s *Store) GetAuthCode(ctx context.Context, code string) (StoreAuthCodeValue, error) {
	d, err := s.client.Get(ctx, code).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return StoreAuthCodeValue{}, errors.New("auth code not found or expired")
		}
		return StoreAuthCodeValue{}, err
	}
	var v StoreAuthCodeValue
	if err := json.Unmarshal(d, &v); err != nil {
		return StoreAuthCodeValue{}, err
	}
	return v, nil
}
