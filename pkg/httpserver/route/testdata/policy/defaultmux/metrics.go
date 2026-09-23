package api

func init() { http.Handle("/metrics", promhttp.Handler()) }
