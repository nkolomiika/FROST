package http

import (
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/users"
)

// userOut — порт UserOut.model_validate: avatar_url вычисляется (nil без аватара),
// role/project_role приводятся к нижнему регистру API.
func userOut(u *users.User) apiv1.UserOut {
	projectRole := apiv1.ProjectRole(strings.ToLower(u.ProjectRole))
	out := apiv1.UserOut{
		Id:                int(u.ID),
		Username:          u.Username,
		Email:             openapi_types.Email(u.Email),
		FullName:          ptrIfNonEmpty(u.FullName),
		Role:              apiv1.UserRole(strings.ToLower(u.Role)),
		ProjectRole:       &projectRole,
		IsActive:          u.IsActive,
		IsLocked:          ptr(u.IsLocked),
		TotpEnabled:       ptr(u.TotpEnabled),
		CreatedAt:         u.CreatedAt,
		PasswordChangedAt: u.PasswordChangedAt,
		AvatarUrl:         avatarURL(u.ID, ptrIfNonEmpty(u.AvatarKey), u.AvatarUploadedAt),
	}
	return out
}

// invitationOut — порт InvitationOut.model_validate (is_expired вычисляется).
func invitationOut(i *users.Invitation) apiv1.InvitationOut {
	return apiv1.InvitationOut{
		Id:          int(i.ID),
		Email:       openapi_types.Email(i.Email),
		FullName:    ptrIfNonEmpty(i.FullName),
		Role:        apiv1.UserRole(strings.ToLower(i.Role)),
		ProjectRole: apiv1.ProjectRole(strings.ToLower(i.ProjectRole)),
		Status:      i.Status,
		ExpiresAt:   i.ExpiresAt,
		CreatedAt:   i.CreatedAt,
		InvitedBy:   int32Ptr(i.InvitedBy),
		IsExpired:   ptr(i.IsExpired(time.Now().UTC())),
	}
}

// emailToPtr: *openapi_types.Email → *string (nil сохраняется).
func emailToPtr(e *openapi_types.Email) *string {
	if e == nil {
		return nil
	}
	s := string(*e)
	return &s
}

// roleToUpperPtr: *apiv1.UserRole (нижний регистр) → *string (верхний, как в БД).
func roleToUpperPtr(r *apiv1.UserRole) *string {
	if r == nil {
		return nil
	}
	s := strings.ToUpper(string(*r))
	return &s
}

// projectRoleToUpperPtr: *apiv1.ProjectRole → *string (верхний регистр БД).
func projectRoleToUpperPtr(r *apiv1.ProjectRole) *string {
	if r == nil {
		return nil
	}
	s := strings.ToUpper(string(*r))
	return &s
}

// roleToUpper: *apiv1.UserRole → строка ("" если nil) для InvitationInput.
func roleToUpper(r *apiv1.UserRole) string {
	if r == nil {
		return ""
	}
	return strings.ToUpper(string(*r))
}

func projectRoleToUpper(r *apiv1.ProjectRole) string {
	if r == nil {
		return ""
	}
	return strings.ToUpper(string(*r))
}

func strOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
