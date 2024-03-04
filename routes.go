package main

import (
	"github.com/gorilla/mux"
)

func defineRoutes(router *mux.Router, s *Server) {
	router.HandleFunc("/api/ping", s.handlePing)
	router.HandleFunc("/api/countries", s.handleListCountries)
	router.HandleFunc("/api/countries/{alpha2}", s.handleGetCountryByAlpha2).Methods("GET")
	router.HandleFunc("/api/auth/register", s.handleRegister).Methods("POST")
	router.HandleFunc("/api/auth/sign-in", s.handleSignIn).Methods("POST")
	router.HandleFunc("/api/me/profile", s.handleGetMyProfile).Methods("GET")
    router.HandleFunc("/api/me/profile", s.handlePatchMyProfile).Methods("PATCH")
	router.HandleFunc("/api/profiles/{login}", s.getProfile).Methods("GET")
	router.HandleFunc("/api/me/updatePassword", s.updatePassword).Methods("POST")
	router.HandleFunc("/api/friends/add", s.addFriend).Methods("POST")
	router.HandleFunc("/api/friends/remove", s.removeFriend).Methods("POST")
	router.HandleFunc("/api/friends", s.listFriends).Methods("GET")
	router.HandleFunc("/api/posts/new", s.submitPost).Methods("POST")
    router.HandleFunc("/api/posts/{postId}", s.getPostById).Methods("GET")
	router.HandleFunc("/api/posts/feed/my", s.getMyFeed).Methods("GET")
    router.HandleFunc("/api/posts/feed/{login}", s.getFeedByOthers).Methods("GET")
	router.HandleFunc("/api/posts/{postId}/like", s.likePost).Methods("POST")
	router.HandleFunc("/api/posts/{postId}/dislike", s.dislikePost).Methods("POST")

}
