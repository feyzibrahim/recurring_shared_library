import Jwt from "jsonwebtoken";

export type JWTPayload = {
  user: string;
  roles: string;
  organization: string;
};

const createJwtAccessToken = (payload: JWTPayload, secret: string): string => {
  return Jwt.sign(
    {
      user: payload.user,
      roles: payload.roles,
      organization: payload.organization,
    },
    secret,
    {
      expiresIn: "1h",
    }
  );
};

const createJwtRefreshToken = (payload: JWTPayload, secret: string): string => {
  return Jwt.sign({ user: payload.user, roles: payload.roles }, secret, {
    expiresIn: "30d",
  });
};

const validateJwt = (token: string, secret: string): JWTPayload => {
  return Jwt.verify(token, secret) as JWTPayload;
};

export { createJwtAccessToken, createJwtRefreshToken, validateJwt };
