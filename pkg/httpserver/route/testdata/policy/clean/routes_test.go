package api

// Tests may build their own mux.
func testMux() { mux := http.NewServeMux(); mux.HandleFunc("/api/v1/x", nil) }
