# JWT_TOKEN_DECODE
jwt decode token using GO


```go

func DecodeServiceAccessAuthToken(req *http.Request, tokenSecret string) (*CustomerInformation, error) {
	authorizationHeader := req.Header.Get("Authorization")
	var parts []string
	if authorizationHeader != "" {
		parts = strings.Split(authorizationHeader, " ")
		if len(parts) == 2 {
			_, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					log.Log().Msgf("Token invalid %v: ", token)
					return nil, fmt.Errorf(" There was an error !")
				}
				return []byte(tokenSecret), nil
			})
			if err != nil {
				log.Error().Err(err)
				return nil, ErrInvalidToken
			}
		} else {
			return nil, ErrInvalidTokenType
		}
	} else {
		return nil, ErrInvalidAuthorizationHeader
	}

	if !slices.Contains(AllowedTokenTypes, strings.ToLower(parts[0])) {
		return nil, ErrInvalidTokenType
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(parts[1], claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if !token.Valid {
		log.Info().Msg("invalid token")
		return nil, ErrInvalidToken
	}

	if err != nil {
		log.Error().Err(err).Msg("token decode error")
		return nil, err
	}

	// Extract the claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims not found")
	}

	// Extract the ID from the claims
	idClaims, ok := claims["id"].(float64)
	if !ok {
		return nil, errors.New("id not found")
	}

	// Extract the StatusId from the claims
	statusIdClaims, ok := claims["statusId"].(float64)
	if !ok {
		return nil, errors.New("statusId not found")
	}

	// Extract the EXP from the claims
	expClaims, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("exp not found")
	}

	//// do something with decoded claims
	//for key, val := range claims {
	//	fmt.Printf("Key: %v, value: %v\n", key, val)
	//}

	info := new(CustomerInformation)

	//SET INFO TO STRUCT
	info.Id = int64(idClaims)
	info.ID = claims["_id"].(string)
	info.FirstName = claims["firstName"].(string)
	info.Phone = claims["phone"].(string)
	info.Email = claims["email"].(string)
	info.Exp = int64(expClaims)
	info.IsEmailVerified = claims["isEmailVerified"].(bool)
	info.IsPhoneVerified = claims["isPhoneVerified"].(bool)
	info.StatusId = int(statusIdClaims)
	info.CreatedAt = claims["createdAt"].(string)
	info.UpdatedAt = claims["updatedAt"].(string)
	info.Iat = claims["iat"].(float64)

	//expirationTime := time.Unix(info.Exp, 0)
	//log.Debug().Msgf("Token expires at: %v", expirationTime)
	//if time.Now().UTC().After(expirationTime) {
	//	log.Debug().Msg("Token has expired")
	//} else {
	//	log.Debug().Msg("Token is still valid")
	//}

	return info, err
}
```
