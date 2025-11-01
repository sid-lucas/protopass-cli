def client_log(level, context, message):
    """Affiche un message formaté de manière cohérente côté client (prépare les futurs logs)."""
    print(f"[{level.upper()}] {context}: {message}")