# Examples

- `traefik-v3/docker-compose.yml` — Docker Compose with Traefik, the forward-auth service, an admin router and a demo app.
- `traefik-v3/kubernetes.yaml` — Kubernetes Deployment, Service, PVC, Traefik middleware and IngressRoutes.

Both examples use placeholder hostnames and Google OAuth credentials. Register
`https://tfa-admin.example.com/auth/callback` for the admin client and
`https://whoami.example.com/_oauth` for the forward-auth client (or a single
`https://auth.example.com/_oauth` when using the auth-host setting).
