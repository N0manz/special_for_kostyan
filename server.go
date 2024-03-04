package main

import (
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	"net/http"
)

type Server struct {
	address string
	logger  *logrus.Logger
	db      *sqlx.DB
}

// Конструктор для создания нового сервера
func NewServer(address string, logger *logrus.Logger, db *sqlx.DB) *Server {
	return &Server{
		address: address,
		logger:  logger,
		db:      db,
	}
}

// Метод для запуска сервера
func (s *Server) Start() error {
	router := mux.NewRouter()
	defineRoutes(router, s)

	s.logger.Info("server has been started", "address", s.address)

	err := http.ListenAndServe(s.address, router)
	if err != nil {
		return err
	}

	return nil
}
