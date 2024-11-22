import secrets
import string
import math
import argparse
import logging

# Konfigurer logging
logging.basicConfig(filename="password_log.txt", level=logging.INFO, 
                    format="%(asctime)s - %(message)s")

def calculate_entropy(password):
    """Beregn passordets entropi basert på karaktervariasjon og lengde."""
    unique_chars = len(set(password))
    entropy = len(password) * math.log2(unique_chars)
    return entropy

def is_blacklisted(password, blacklist):
    """Sjekk om passordet inneholder uønskede ord eller mønstre."""
    return any(item in password for item in blacklist)

def generate_random_password(length=16, min_uppercase=2, min_lowercase=2, 
                             min_digits=2, min_symbols=2, 
                             avoid_similar=True, avoid_ambiguous=True,
                             blacklist=None):
    """
    Generer et komplekst passord med spesifikke krav.

    :param length: Total lengde på passordet.
    :param min_uppercase: Minimum antall store bokstaver.
    :param min_lowercase: Minimum antall små bokstaver.
    :param min_digits: Minimum antall tall.
    :param min_symbols: Minimum antall spesialtegn.
    :param avoid_similar: Unngå like tegn som O, 0, I, l.
    :param avoid_ambiguous: Unngå tvetydige tegn som {}, [].
    :param blacklist: Liste over forbudte mønstre eller ord.
    :return: Generert passord.
    """
    # Tegnsett
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation
    
    if avoid_similar:
        similar_chars = "O0I1l"
        uppercase = ''.join(c for c in uppercase if c not in similar_chars)
        lowercase = ''.join(c for c in lowercase if c not in similar_chars)
        digits = ''.join(c for c in digits if c not in similar_chars)
    
    if avoid_ambiguous:
        ambiguous_chars = "{}[]()/\\'\"`~,;:.<>"
        symbols = ''.join(c for c in symbols if c not in ambiguous_chars)
    
    # Sjekk at passordlengden er tilstrekkelig for kravene
    required_length = min_uppercase + min_lowercase + min_digits + min_symbols
    if length < required_length:
        raise ValueError("Passordlengden er for kort for de spesifiserte kravene.")
    
    # Bygg passord
    password_chars = (
        [secrets.choice(uppercase) for _ in range(min_uppercase)] +
        [secrets.choice(lowercase) for _ in range(min_lowercase)] +
        [secrets.choice(digits) for _ in range(min_digits)] +
        [secrets.choice(symbols) for _ in range(min_symbols)]
    )
    remaining_length = length - len(password_chars)
    all_chars = uppercase + lowercase + digits + symbols
    password_chars += [secrets.choice(all_chars) for _ in range(remaining_length)]
    
    # Bland rekkefølgen
    secrets.SystemRandom().shuffle(password_chars)
    password = ''.join(password_chars)
    
    # Sjekk mot blacklist
    if blacklist and is_blacklisted(password, blacklist):
        return generate_random_password(length, min_uppercase, min_lowercase, 
                                        min_digits, min_symbols, avoid_similar, 
                                        avoid_ambiguous, blacklist)
    
    # Loggfør passord (kun for testing, slett for produksjon)
    logging.info(f"Generated password: {password}")
    
    return password

def generate_passphrase(num_words=4, delimiter="-", blacklist=None):
    """
    Generer en passordsetning basert på tilfeldige ord.
    """
    wordlist = [
        "apple", "banana", "cherry", "dragon", "elephant", 
        "fox", "giraffe", "hippo", "iguana", "jellyfish"
    ]
    passphrase = delimiter.join(secrets.choice(wordlist) for _ in range(num_words))
    if blacklist and is_blacklisted(passphrase, blacklist):
        return generate_passphrase(num_words, delimiter, blacklist)
    logging.info(f"Generated passphrase: {passphrase}")
    return passphrase

def main():
    # Argumentparsing
    parser = argparse.ArgumentParser(description="Avansert passordgenerator")
    parser.add_argument("--length", type=int, default=16, help="Lengde på passordet")
    parser.add_argument("--min-uppercase", type=int, default=2, help="Minimum store bokstaver")
    parser.add_argument("--min-lowercase", type=int, default=2, help="Minimum små bokstaver")
    parser.add_argument("--min-digits", type=int, default=2, help="Minimum tall")
    parser.add_argument("--min-symbols", type=int, default=2, help="Minimum spesialtegn")
    parser.add_argument("--avoid-similar", action="store_true", help="Unngå like tegn som O, 0, I, l")
    parser.add_argument("--avoid-ambiguous", action="store_true", help="Unngå tvetydige tegn som {}, []")
    parser.add_argument("--blacklist", nargs="+", help="Forbudte ord eller mønstre")
    parser.add_argument("--passphrase", action="store_true", help="Generer passordsetning i stedet")
    parser.add_argument("--num-words", type=int, default=4, help="Antall ord i passordsetning")
    args = parser.parse_args()
    
    # Generer passord eller passordsetning
    if args.passphrase:
        password = generate_passphrase(num_words=args.num_words, blacklist=args.blacklist)
    else:
        password = generate_random_password(
            length=args.length,
            min_uppercase=args.min_uppercase,
            min_lowercase=args.min_lowercase,
            min_digits=args.min_digits,
            min_symbols=args.min_symbols,
            avoid_similar=args.avoid_similar,
            avoid_ambiguous=args.avoid_ambiguous,
            blacklist=args.blacklist
        )
    
    # Vis resultat og entropi
    print(f"Generert passord: {password}")
    entropy = calculate_entropy(password)
    print(f"Entropi: {entropy:.2f} bits")
    print("Passordstyrke: ", end="")
    if entropy < 50:
        print("Svak")
    elif entropy < 80:
        print("Middels")
    else:
        print("Sterk")

if __name__ == "__main__":
    main()
