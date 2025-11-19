import random
import secrets
from dataclasses import dataclass

"""
Génération de mot de passe inspirée de 'password_generator.rs' de Proton Pass
"""

# Conteneur d'options à la Proton Pass (RandomPasswordConfig)
@dataclass
class PasswordOptions:
    length: int = 20
    digits: bool = True
    lowercase: bool = True
    uppercase: bool = True
    symbols: bool = True

# Sets identiques à ceux utilise par Proton Pass (caractères ambigus exclus)
LOWERCASE_LETTERS = "abcdefghjkmnpqrstuvwxyz"
UPPERCASE_LETTERS = "ABCDEFGHJKMNPQRSTUVWXYZ"
NUMBERS = "0123456789"
SYMBOLS = "!@#$%^&*"

def _build_dictionary(options: PasswordOptions) -> str:
    """
    Construction du dictionnaire utilisé pour les tirages
    """
    # Concatène les sets selon la configuration.
    dictionary = LOWERCASE_LETTERS if options.lowercase else ""
    if options.uppercase:
        dictionary += UPPERCASE_LETTERS
    if options.digits:
        dictionary += NUMBERS
    if options.symbols:
        dictionary += SYMBOLS
    return dictionary

def _pick_char(include: bool, charset: str, current_chars: list[str], dictionary: str) -> str:
    """
    Sélectionne un caractère en forçant la catégorie si elle manque
    """
    # Si l'option est activée et absente du mot de passe, on pioche dans la catégorie
    if include and not any(char in charset for char in current_chars):
        return secrets.choice(charset)
    return secrets.choice(dictionary)

# Point d'entrée principal (kwargs ou PasswordOptions)
def generate_password(
    *,
    options: PasswordOptions | None = None,
    length: int = 20,
    digits: bool = True,
    lowercase: bool = True,
    uppercase: bool = True,
    symbols: bool = True,
) -> str:
    """
    Génère un mot de passe (ASCII) avec la même politique que Proton Pass.
    Accepte soit un PasswordOptions, soit les paramètres individuels.
    """

    # Favorise l'objet d'options quand il est fourni
    opts = options or PasswordOptions(
        length=length,
        digits=digits,
        lowercase=lowercase,
        uppercase=uppercase,
        symbols=symbols,
    )

    # retourne une chaîne vide si longueur choisie = 0
    if opts.length == 0:
        return ""

    # Construction de la pool et garde-fou si toutes les catégories sont désactivées
    dictionary = _build_dictionary(opts)
    if not dictionary:
        raise ValueError("Au moins une catégorie doit être activée.")

    # Politique "best effort" pour les longueurs <= 3
    # (fait de son mieux quand la contrainte est irréalisable à cause d’une longueur trop courte)
    if opts.length <= 3:
        return "".join(secrets.choice(dictionary) for _ in range(opts.length))

    # Best-effort: on tire length-3 caractères puis on ajoute les catégories obligatoires.
    password_chars: list[str] = [secrets.choice(dictionary) for _ in range(opts.length - 3)]

    # Ajoute les catégories qui pourraient manquer
    for include, charset in (
        (opts.uppercase, UPPERCASE_LETTERS),
        (opts.digits, NUMBERS),
        (opts.symbols, SYMBOLS),
    ):
        password_chars.append(_pick_char(include, charset, password_chars, dictionary))

    # Mélange final pour éviter que les caractères forcés soient regroupés
    random.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
