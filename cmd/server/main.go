package main

import (
	"log"
	"net/http"

	"github.com/fchimpan/go-oauth2-server/internal/handler"
	"github.com/fchimpan/go-oauth2-server/internal/store"
)

func main() {
	db := store.NewStore()
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	ah := handler.NewAuthorizeHandler(db)
	th := handler.NewTokenHandler(db)
	http.HandleFunc("/authorize", ah.Handle)
	http.HandleFunc("/token", th.Handle)

	log.Println("Server is running on :8088")

	http.ListenAndServe(":8088", nil)
}
