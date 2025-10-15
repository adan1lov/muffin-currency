package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type CurrencyRate struct {
	From   string  `json:"from"`
	To     string  `json:"to"`
	Rate   float64 `json:"rate"`
}

var rates = map[string]map[string]float64{
	"CARAMEL": {"CHOKOLATE": 0.85, "PLAIN": 75.50},
	"CHOKOLATE": {"CARAMEL": 1.18, "PLAIN": 89.00},
	"PLAIN": {"CHOKOLATE": 0.013, "CARAMEL": 0.011},
}

func getRateHandler(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	if from == "" || to == "" {
		http.Error(w, "Missing 'from' or 'to' parameter", http.StatusBadRequest)
		return
	}

	rate, exists := rates[from][to]
	if !exists {
		http.Error(w, "Currency pair not found", http.StatusNotFound)
		return
	}

	response := CurrencyRate{
		From: from,
		To:   to,
		Rate: rate,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/rate", getRateHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
