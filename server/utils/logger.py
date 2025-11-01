
def log_server(level, context, message):
    """Affiche un message formaté de manière cohérente côté serveur (prépare les futurs logs)."""
    print(f"[{level.upper()}] [{context}] {message}")
