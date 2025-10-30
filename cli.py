import argparse

def main():
    # Création parseur de commandes
    parser = argparse.ArgumentParser(
        prog="protoncli",
        description="Prototype password manager CLI"
    )

    args = parser.parse_args()

    print("CLI prêt (aucune commande définie).")

if __name__ == "__main__":
    main()
