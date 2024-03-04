package main
import(
	"time"
)
type Country struct {
	Name   string `db:"name" json:"name"`
	Alpha2 string `db:"alpha2" json:"alpha2"`
	Alpha3 string `db:"alpha3" json:"alpha3"`
	Region string `db:"region" json:"region"`
}

type User struct {
	ID          string  `json:"id" db:"id"`
	Login       string  `json:"login" db:"login"`
	Email       string  `json:"email" db:"email"`
	Password    string  `json:"password" db:"password"`
	CountryCode *string `json:"countryCode" db:"country_code"`
	IsPublic    *bool    `json:"isPublic" db:"is_public"`
	Phone       *string  `json:"phone" db:"phone"`
	Image       *string  `json:"image" db:"image"`
}


type UserProfile struct {
    Login    string `json:"login"`
    IsPublic bool   `json:"isPublic"` // Используйте bool, если не требуется специальная обработка NULL
}

type Post struct {
    ID            string    `json:"id"`
    Content       string    `json:"content"`
    Author        string    `json:"author"`
    Tags          []string  `json:"tags"`
    CreatedAt     time.Time `json:"createdAt"`
    LikesCount    int       `json:"likesCount"`
    DislikesCount int       `json:"dislikesCount"`
}
