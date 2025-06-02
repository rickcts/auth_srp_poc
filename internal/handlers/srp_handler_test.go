package handlers_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goccy/go-json"

	"github.com/SimpnicServerTeam/scs-aaa-server/internal/handlers"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/mocks"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/models"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/repository"
	"github.com/SimpnicServerTeam/scs-aaa-server/internal/router"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupTestApp(mockAuthService *mocks.MockSRPAuthService) *fiber.App {
	app := fiber.New()
	authHandler := handlers.NewSRPAuthHandler(mockAuthService)
	router.SetupSRPRoutes(app, authHandler)
	return app
}

func performRequest(app *fiber.App, method, path string, body any) *http.Response {
	var reqBody io.Reader = nil
	if body != nil {
		jsonData, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonData)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")

	resp, _ := app.Test(req, -1) // -1 disables timeout
	return resp
}

func TestAuthHandler_Register(t *testing.T) {
	// Common request data can stay outsIDe
	registerReq := models.SRPRegisterRequest{
		AuthID:      "auth1@example.com",
		DisplayName: "newuser",
		Salt:        "salt123",
		Verifier:    "verifier123",
	}

	t.Run("Success", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		mockAuthService.On("Register", registerReq).Return(nil).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/sign-up", registerReq)

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("BadRequestInvalIDJSON", func(t *testing.T) {
		// Setup insIDe subtest (need app, even if mock isn't called)
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		req := httptest.NewRequest("POST", "/api/auth/srp/sign-up", bytes.NewBufferString("{invalID json"))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := app.Test(req, -1)

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		// No mock call expected for bad parsing
		mockAuthService.AssertNotCalled(t, "Register", mock.Anything)
		// Assert expectations to catch any unexpected calls
		mockAuthService.AssertExpectations(t)
	})

	t.Run("ConflictUserExists", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		serviceErr := fmt.Errorf("service layer message: %w", repository.ErrUserExists)
		mockAuthService.On("Register", registerReq).Return(serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/sign-up", registerReq)

		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Username already exists", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("InternalServerError", func(t *testing.T) {
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		serviceErr := errors.New("some internal service error")
		mockAuthService.On("Register", registerReq).Return(serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/sign-up", registerReq)

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Registration failed", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_AuthStep1(t *testing.T) {
	// Common request/response data can stay outsIDe
	step1Req := models.AuthStep1Request{AuthID: "testuser@example.com"}
	step1Resp := models.AuthStep1Response{Salt: "salt123", ServerB: "serverB123"}

	t.Run("Success", func(t *testing.T) {
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		mockAuthService.On("ComputeB", step1Req).Return(&step1Resp, nil).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/email", step1Req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actualResp models.AuthStep1Response
		err := json.NewDecoder(resp.Body).Decode(&actualResp)
		require.NoError(t, err)
		assert.Equal(t, step1Resp, actualResp)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("BadRequestInvalIDJSON", func(t *testing.T) {
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		req := httptest.NewRequest("POST", "/api/auth/srp/login/email", bytes.NewBufferString("{invalID json"))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := app.Test(req, -1)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		mockAuthService.AssertNotCalled(t, "ComputeB", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("UserNotFound", func(t *testing.T) {
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		// Simulate service returning ErrUserNotFound (wrapped)
		serviceErr := fmt.Errorf("service layer message: %w", repository.ErrUserNotFound)
		mockAuthService.On("ComputeB", step1Req).Return(nil, serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/email", step1Req)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "User not found", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("InternalServerError", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		serviceErr := errors.New("some internal service error")
		mockAuthService.On("ComputeB", step1Req).Return(nil, serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/email", step1Req)

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Authentication initiation failed", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})
}

func TestAuthHandler_AuthStep2(t *testing.T) {
	// Common request/response data can stay outsIDe
	step2Req := models.AuthStep2Request{
		AuthID:        "testuser@example.com",
		ClientA:       "clientA123",
		ClientProofM1: "clientM1123",
	}
	step2Resp := models.AuthStep3Response{
		ServerProofM2: "serverM2abc",
		SessionToken:  "jwt.token.string",
	}

	t.Run("Success", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		mockAuthService.On("VerifyClientProof", step2Req).Return(&step2Resp, nil).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/proof", step2Req)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actualResp models.AuthStep3Response
		err := json.NewDecoder(resp.Body).Decode(&actualResp)
		require.NoError(t, err)
		assert.Equal(t, step2Resp, actualResp)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("BadRequestInvalIDJSON", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		req := httptest.NewRequest("POST", "/api/auth/srp/login/proof", bytes.NewBufferString("{invalID json"))
		req.Header.Set("Content-Type", "application/json")
		resp, _ := app.Test(req, -1)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		mockAuthService.AssertNotCalled(t, "VerifyClientProof", mock.Anything)
		mockAuthService.AssertExpectations(t)
	})

	t.Run("UnauthorizedStateNotFound", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		// Simulate service returning ErrStateNotFound (wrapped)
		serviceErr := fmt.Errorf("service layer message: %w", repository.ErrStateNotFound)
		mockAuthService.On("VerifyClientProof", step2Req).Return(nil, serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/proof", step2Req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Authentication session expired or invalID", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("UnauthorizedInvalIDProof", func(t *testing.T) {
		// Setup insIDe subtest
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		serviceErr := errors.New("client proof M1 verification failed")
		mockAuthService.On("VerifyClientProof", step2Req).Return(nil, serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/proof", step2Req)

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "InvalID client credentials", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})

	t.Run("InternalServerError", func(t *testing.T) {
		mockAuthService := new(mocks.MockSRPAuthService)
		app := setupTestApp(mockAuthService)

		serviceErr := errors.New("some other internal service error")
		mockAuthService.On("VerifyClientProof", step2Req).Return(nil, serviceErr).Once()

		resp := performRequest(app, "POST", "/api/auth/srp/login/proof", step2Req)

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var errResp models.ErrorResponse
		err := json.NewDecoder(resp.Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "Authentication verification failed", errResp.Error)

		mockAuthService.AssertExpectations(t)
	})
}
