package main

import (
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib" // Импорт драйвера PostgreSQL
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus" // Предположим, что используется logrus для логгирования
)

func main() {
	// Инициализация логгера
	logger := logrus.New()
	logger.Formatter = &logrus.JSONFormatter{}

	// Получение строки подключения к PostgreSQL из переменных окружения
	pgURL := os.Getenv("POSTGRES_CONN")
	if pgURL == "" {
		logger.Error("missed POSTGRES_CONN env")
		os.Exit(1)
	}

	// Подключение к базе данных
	db, err := sqlx.Connect("pgx", pgURL)
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	// Получение адреса сервера из переменных окружения
	serverAddress := os.Getenv("SERVER_ADDRESS")
	if serverAddress == "" {
		logger.Error("missed SERVER_ADDRESS env")
		os.Exit(1)
	}

	// Создание экземпляра сервера с передачей логгера и базы данных
	s := NewServer(serverAddress, logger, db) // Обратите внимание на добавленный аргумент db

	// Запуск сервера
	err = s.Start()
	if err != nil {
		logger.Error("server has been stopped", "error", err)
	}
}
