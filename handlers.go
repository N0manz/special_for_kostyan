package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"time"
    "database/sql"
)

func checkPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// Обработчик списка стран
func (s *Server) handleListCountries(w http.ResponseWriter, r *http.Request) {
	var countries []Country
	query := "SELECT name, alpha2, alpha3, region FROM countries"
	if region := r.URL.Query().Get("region"); region != "" {
		query += " WHERE region = $1"
		if err := s.db.Select(&countries, query, region); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if err := s.db.Select(&countries, query); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(countries)
}

// Обработчик для получения страны по Alpha2 коду
func (s *Server) handleGetCountryByAlpha2(w http.ResponseWriter, r *http.Request) {
	alpha2 := mux.Vars(r)["alpha2"]
	var country Country
	query := "SELECT name, alpha2, alpha3, region FROM countries WHERE alpha2 = $1"
	if err := s.db.Get(&country, query, alpha2); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(country)
}

// Обработчик для проверки работоспособности сервера
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Функция для проверки уникальности email и login
func (s *Server) isUniqueUser(email, login string) (bool, error) {
	var count int
	err := s.db.Get(&count, "SELECT COUNT(*) FROM users WHERE email = $1 OR login = $2", email, login)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func sendError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	reason := strconv.Itoa(statusCode) // Преобразование статус-кода в строку
	json.NewEncoder(w).Encode(map[string]string{"reason": reason, "response": message})
}

// Проверка на существование кода страны
func (s *Server) isValidCountryCode(countryCode *string) (bool, error) {
	var count int
	err := s.db.Get(&count, "SELECT COUNT(*) FROM countries WHERE alpha2 = $1", countryCode)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var newUser User
	// Декодирование JSON тела запроса в структуру newUser
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body") // Корректируем сообщение об ошибке
		return
	}

	if len(newUser.Password) < 8 {
		sendError(w, http.StatusBadRequest, "Password is not secure enough")
		return
	}

	unique, err := s.isUniqueUser(newUser.Email, newUser.Login)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if !unique {
		sendError(w, http.StatusConflict, "User with this email, phone number, or login is already registered")
		return
	}

	// Проверка countryCode, если он предоставлен
	if newUser.CountryCode != nil {
		validCountry, err := s.isValidCountryCode(newUser.CountryCode)
		if err != nil || !validCountry {
			sendError(w, http.StatusBadRequest, "Country code not found")
			return
		}
	}

	// Проверка длины Image URL, если он предоставлен
	if newUser.Image != nil {
		if newUser.Image != nil && len(*newUser.Image) > 255 {
			sendError(w, http.StatusBadRequest, "Image URL exceeds the length limit")
			return
		}
	}

	hashedPassword, err := hashPassword(newUser.Password)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}
	newUser.Password = hashedPassword

	// Setting isPublic to true if not specified
	isPublic := true
	if newUser.IsPublic != nil {
		isPublic = *newUser.IsPublic
	}

	_, err = s.db.Exec("INSERT INTO users (login, email, password, country_code, is_public, phone, image) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		newUser.Login, newUser.Email, newUser.Password, newUser.CountryCode, isPublic, newUser.Phone, newUser.Image)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error saving user")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User successfully registered"})
}

var jwtKey = []byte("your_secret_key") // Используйте секретный ключ для подписи токена

// Функция для генерации JWT
func generateJWT(userID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Токен действителен 24 часа
	claims := &jwt.StandardClaims{
		Subject:   userID,
		ExpiresAt: expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	return tokenString, err
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Инициализация структуры для хранения данных пользователя из БД
	var user struct {
		ID       string `db:"id"`
		Password string `db:"password"` // Хешированный пароль
	}

	// Запрос к базе данных для получения хешированного пароля пользователя
	err = s.db.Get(&user, "SELECT id, password FROM users WHERE login = $1", credentials.Login)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "Login or password is incorrect")
		return
	}

	// Сравнение предоставленного пароля с хешированным паролем из базы данных
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		// Пароль не совпадает
		sendError(w, http.StatusUnauthorized, "Login or password is incorrect")
		return
	}

	// Генерация JWT для пользователя
	token, err := generateJWT(user.ID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Отправка токена пользователю
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func verifyToken(tokenString string) (userID string, valid bool) {
	claims := &jwt.StandardClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return "", false
	}

	if !token.Valid {
		return "", false
	}

	return claims.Subject, true
}

func (s *Server) handleGetMyProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:] // Обрезаем "Bearer "
	log.Printf("Token: %s\n", tokenString)           // Добавьте логирование токена для проверки

	userID, valid := verifyToken(tokenString)
	log.Printf("UserID: %s, Valid: %t\n", userID, valid) // Логирование результатов верификации

	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var userProfile User
	err := s.db.Get(&userProfile, "SELECT * FROM users WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error retrieving user profile: %v\n", err) // Логирование ошибки запроса к БД
		sendError(w, http.StatusInternalServerError, "Error retrieving user profile")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userProfile)
}

func (s *Server) handlePatchMyProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:] // Обрезаем "Bearer "
	userID, valid := verifyToken(tokenString)
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	var updates map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&updates)
	if err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Проверка уникальности номера телефона, если он обновляется
	if phone, ok := updates["phone"]; ok {
		var exists bool
		err := s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1 AND id != $2)", phone, userID)
		if err != nil || exists {
			sendError(w, http.StatusConflict, "Phone number already in use by another user")
			return
		}
	}

	// Проверка валидности кода страны, если он обновляется
	if countryCode, ok := updates["countryCode"]; ok && countryCode != "" {
		var exists bool
		err := s.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM countries WHERE alpha2 = $1)", countryCode)
		if err != nil || !exists {
			sendError(w, http.StatusBadRequest, "Country code not found")
			return
		}
	}

	// Создание и выполнение запроса на обновление профиля
	query, args, err := sqlx.Named(`UPDATE users SET country_code = :country_code, is_public = :is_public, phone = :phone, image = :image WHERE id = :id`, map[string]interface{}{
		"country_code": updates["countryCode"],
		"is_public":    updates["isPublic"],
		"phone":        updates["phone"],
		"image":        updates["image"],
		"id":           userID,
	})
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error preparing update query")
		return
	}

	query, args, err = sqlx.In(query, args...)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error preparing query arguments")
		return
	}

	query = s.db.Rebind(query)
	_, err = s.db.Exec(query, args...)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error updating user profile")
		return
	}

	// Извлечение и отправка обновленного профиля
	var updatedProfile User
	err = s.db.Get(&updatedProfile, "SELECT login, email, country_code, is_public, phone, image FROM users WHERE id = $1", userID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error retrieving updated profile")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedProfile)
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestedLogin := vars["login"]

	tokenString := r.Header.Get("Authorization")[7:] // Обрезаем "Bearer "
	requestingUserID, valid := verifyToken(tokenString)
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var requestedUser User
	err := s.db.Get(&requestedUser, "SELECT id, login, is_public FROM users WHERE login = $1", requestedLogin)
	if err != nil {
		sendError(w, http.StatusForbidden, "User not found or access denied")
		return
	}

	// Доступ к полям с учетом указателей
	isPublic := requestedUser.IsPublic != nil && *requestedUser.IsPublic // Разыменование IsPublic, если оно не nil
	canAccess := isPublic || requestedUser.ID == requestingUserID

	if canAccess {
		userProfile := UserProfile{
			Login:    requestedUser.Login,
			IsPublic: isPublic,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userProfile)
	} else {
		sendError(w, http.StatusForbidden, "Access to the profile is denied")
	}
}

func (s *Server) updatePassword(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:] // Обрезаем "Bearer "
	userID, valid := verifyToken(tokenString)
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var passwords struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&passwords); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Проверка длины нового пароля
	if len(passwords.NewPassword) < 8 {
		sendError(w, http.StatusBadRequest, "New password does not meet security requirements")
		return
	}

	var currentHashedPassword string
	err := s.db.Get(&currentHashedPassword, "SELECT password FROM users WHERE id = $1", userID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Проверка старого пароля
	if !checkPasswordHash(passwords.OldPassword, currentHashedPassword) {
		sendError(w, http.StatusForbidden, "Old password is incorrect")
		return
	}

	// Хеширование и обновление нового пароля
	newHashedPassword, err := hashPassword(passwords.NewPassword)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}

	if _, err := s.db.Exec("UPDATE users SET password = $1 WHERE id = $2", newHashedPassword, userID); err != nil {
		sendError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Деактивация старых токенов
	// Эта часть будет зависеть от вашей системы управления токенами.
	// Возможно, вам придется реализовать логику инвалидации токенов.

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) addFriend(w http.ResponseWriter, r *http.Request) {
	// Верификация токена пользователя
	requesterID, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var request struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Получаем userID для логина, указанного в запросе
	var friendID string
	err := s.db.Get(&friendID, "SELECT id FROM users WHERE login = $1", request.Login)
	if err != nil {
		sendError(w, http.StatusNotFound, "User not found")
		return
	}

	// Проверка на добавление себя в друзья
	if friendID == requesterID {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// Проверяем, есть ли уже такая запись в друзьях
	var exists int
	err = s.db.Get(&exists, "SELECT COUNT(*) FROM friends WHERE user_id = $1 AND friend_id = $2", requesterID, friendID)
	if err != nil || exists > 0 {
		// Если запись уже существует, возвращаем успешный ответ
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// Добавляем запись о дружбе
	_, err = s.db.Exec("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)", requesterID, friendID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error adding friend")
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) removeFriend(w http.ResponseWriter, r *http.Request) {
	requesterID, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var request struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var friendID string
	err := s.db.Get(&friendID, "SELECT id FROM users WHERE login = $1", request.Login)
	if err != nil {
		sendError(w, http.StatusNotFound, "User not found")
		return
	}

	_, err = s.db.Exec("DELETE FROM friends WHERE user_id = $1 AND friend_id = $2", requesterID, friendID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error removing friend")
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) listFriends(w http.ResponseWriter, r *http.Request) {
	requesterID, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = 10 // Значение по умолчанию, если параметр не задан или задан неверно
	}

	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil || offset < 0 {
		offset = 0 // Значение по умолчанию
	}

	var friends []struct {
		Login   string `db:"login" json:"login"`
		AddedAt string `db:"added_at" json:"addedAt"`
	}

	err = s.db.Select(&friends, "SELECT u.login, f.added_at FROM friends f JOIN users u ON f.friend_id = u.id WHERE f.user_id = $1 ORDER BY f.added_at DESC LIMIT $2 OFFSET $3", requesterID, limit, offset)
	if err != nil {
		return
	}

	json.NewEncoder(w).Encode(friends)
}

func (s *Server) canViewPosts(requesterID, userID string) bool {
	if requesterID == userID {
		return true
	}
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM friends WHERE user_id = $1 AND friend_id = $2", userID, requesterID).Scan(&count)
	if err != nil || count == 0 {
		return false
	}
	return true
}

func getPaginationParams(r *http.Request) (int, int) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10 // значение по умолчанию
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0 // значение по умолчанию
	}
	return limit, offset
}

func (s *Server) getUserIDByLogin(login string) (string, error) {
	var userID string
	err := s.db.QueryRow("SELECT id FROM users WHERE login = $1", login).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Server) savePostToDB(post Post) (string, error) {
	var postID string
	err := s.db.QueryRow("INSERT INTO posts (content, author, tags, created_at) VALUES ($1, $2, $3, $4) RETURNING id", post.Content, post.Author, pq.Array(post.Tags), post.CreatedAt).Scan(&postID)
	if err != nil {
		return "", err
	}
	return postID, nil
}

func (s *Server) submitPost(w http.ResponseWriter, r *http.Request) {
	userLogin, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	var post Post
	if err := json.NewDecoder(r.Body).Decode(&post); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	post.Author = userLogin     // Установка автора поста
	post.CreatedAt = time.Now() // Установка времени создания

	postID, err := s.savePostToDB(post)
	if err != nil {
		log.Println(err)
		sendError(w, http.StatusInternalServerError, "Error saving the post")
		return
	}

	post.ID = postID
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(post)
}

func (s *Server) getPostFromDB(postID string) (Post, error) {
	var post Post

	// SQL запрос для получения поста по ID
	query := `
    SELECT id, content, author, tags, created_at, likes_count, dislikes_count 
    FROM posts 
    WHERE id = $1`

	err := s.db.QueryRow(query, postID).Scan(&post.ID, &post.Content, &post.Author, pq.Array(&post.Tags), &post.CreatedAt, &post.LikesCount, &post.DislikesCount)
	if err != nil {
		return Post{}, err
	}

	return post, nil
}

func (s *Server) getPostById(w http.ResponseWriter, r *http.Request) {
	_, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	vars := mux.Vars(r)
	postID := vars["postId"]

	post, err := s.getPostFromDB(postID)
	if err != nil {
		sendError(w, http.StatusNotFound, "Post not found")
		return
	}

	json.NewEncoder(w).Encode(post)
}

func (s *Server) getUserPosts(userLogin string, limit int, offset int) ([]Post, error) {
	var posts []Post

	// Подготовка SQL-запроса для получения постов пользователя с пагинацией
	query := `
SELECT id, content, author, tags, created_at, likes_count, dislikes_count
FROM posts
WHERE author = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3`

	rows, err := s.db.Query(query, userLogin, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var post Post
		var tags []string
		err := rows.Scan(&post.ID, &post.Content, &post.Author, pq.Array(&tags), &post.CreatedAt, &post.LikesCount, &post.DislikesCount)
		if err != nil {
			return nil, err
		}
		post.Tags = tags
		posts = append(posts, post)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return posts, nil
}

func (s *Server) getMyFeed(w http.ResponseWriter, r *http.Request) {
	userLogin, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	limit, offset := getPaginationParams(r)

	// Запрос к базе данных для получения постов пользователя с пагинацией
	posts, err := s.getUserPosts(userLogin, limit, offset)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error retrieving posts")
		return
	}

	json.NewEncoder(w).Encode(posts)
}

func (s *Server) getFeedByOthers(w http.ResponseWriter, r *http.Request) {
	_, valid := verifyToken(r.Header.Get("Authorization")[7:])
	if !valid {
		sendError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	vars := mux.Vars(r)
	userLogin := vars["login"]

	limit, offset := getPaginationParams(r)

	// Запрос к базе данных для получения постов указанного пользователя с пагинацией
	posts, err := s.getUserPosts(userLogin, limit, offset)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "Error retrieving posts")
		return
	}

	json.NewEncoder(w).Encode(posts)
}

func (s *Server) updatePostLikes(postID string, like bool) error {
	column := "dislikes_count"
	if like {
		column = "likes_count"
	}

	query := fmt.Sprintf("UPDATE posts SET %s = %s + 1 WHERE id = $1", column, column)
	_, err := s.db.Exec(query, postID)
	return err
}

func (s *Server) likePost(w http.ResponseWriter, r *http.Request) {
    _, valid := verifyToken(r.Header.Get("Authorization")[7:])
    if !valid {
        sendError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    vars := mux.Vars(r)
    postID := vars["postId"]

    // Предполагая, что updatePostLikes возвращает ошибку sql.ErrNoRows, если пост не найден
    if err := s.updatePostLikes(postID, true); err != nil {
        if err == sql.ErrNoRows {
            sendError(w, http.StatusNotFound, "Post not found")
            return
        }
        sendError(w, http.StatusInternalServerError, "Error updating post likes")
        return
    }

    post, err := s.getPostFromDB(postID)
    if err != nil {
        sendError(w, http.StatusInternalServerError, "Error retrieving the post")
        return
    }

    json.NewEncoder(w).Encode(post)
}

func (s *Server) updatePostDislikes(postID string) error {
    query := `UPDATE posts SET dislikes_count = dislikes_count + 1 WHERE id = $1 RETURNING id`
    _, err := s.db.Exec(query, postID)
    return err
}

func (s *Server) dislikePost(w http.ResponseWriter, r *http.Request) {
    _, valid := verifyToken(r.Header.Get("Authorization")[7:])
    if !valid {
        sendError(w, http.StatusUnauthorized, "Invalid or expired token")
        return
    }

    vars := mux.Vars(r)
    postID := vars["postId"]

    // Обновление счетчика дизлайков для поста
    if err := s.updatePostDislikes(postID); err != nil {
        if err == sql.ErrNoRows {
            sendError(w, http.StatusNotFound, "Post not found")
        } else {
            sendError(w, http.StatusInternalServerError, "Error updating post dislikes")
        }
        return
    }

    // Получение обновленного поста для отображения актуального количества лайков и дизлайков
    post, err := s.getPostFromDB(postID)
    if err != nil {
        sendError(w, http.StatusInternalServerError, "Error retrieving the post")
        return
    }

    json.NewEncoder(w).Encode(post)
}

