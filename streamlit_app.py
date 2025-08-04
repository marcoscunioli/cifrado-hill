import streamlit as st
import numpy as np
import math

# --- Hill Cipher Constants ---
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = len(ALPHABET)

# --- Helper Functions for Matrix Operations ---

def mod_inverse(a, m):
    """Calculates the modular multiplicative inverse of 'a' modulo 'm'."""
    # This function is crucial for finding the inverse of the determinant
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None # Inverse does not exist

def matrix_mult(A, B, m):
    """Multiplies two matrices A and B modulo m."""
    # A is key matrix (n x n), B is message vector (n x 1)
    # Ensure A and B are numpy arrays for easier multiplication
    A = np.array(A)
    B = np.array(B)

    # If B is a 1D array (vector), convert it to a column vector for multiplication
    if B.ndim == 1:
        B = B.reshape(-1, 1) # Convert to column vector

    result = np.dot(A, B) % m
    return result

def determinant_2x2(matrix):
    """Calculates the determinant of a 2x2 matrix."""
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])

def adjugate_2x2(matrix):
    """Calculates the adjugate of a 2x2 matrix."""
    return np.array([
        [matrix[1][1], -matrix[0][1]],
        [-matrix[1][0], matrix[0][0]]
    ])

def matrix_inverse_2x2(matrix, m):
    """Calculates the modular inverse of a 2x2 matrix modulo m."""
    det = determinant_2x2(matrix)
    det_mod = det % m

    det_inv = mod_inverse(det_mod, m)
    if det_inv is None:
        return None # Inverse does not exist

    adj = adjugate_2x2(matrix)
    
    # Apply modular inverse to each element of the adjugate matrix
    # Ensure all elements are positive before modulo
    inv_matrix = (det_inv * adj) % m
    return inv_matrix

def parse_key_matrix(key_str):
    """Parses a string input into a square matrix."""
    rows = key_str.strip().split('\n')
    matrix = []
    for row_str in rows:
        # Split by comma or space, filter out empty strings
        elements = [int(x.strip()) for x in row_str.replace(',', ' ').split() if x.strip()]
        matrix.append(elements)
    
    # Validate if it's a square matrix
    num_rows = len(matrix)
    if num_rows == 0:
        return None, "La matriz clave no puede estar vacía."
    
    for row in matrix:
        if len(row) != num_rows:
            return None, "La matriz clave debe ser cuadrada."
    
    return matrix, None

def prepare_message(message, block_size):
    """
    Prepares the message for encryption:
    1. Converts to uppercase.
    2. Removes non-alphabetic characters.
    3. Pads with 'X' if length is not a multiple of block_size.
    """
    processed_message = "".join(char for char in message.upper() if char.isalpha())
    
    if len(processed_message) % block_size != 0:
        padding_needed = block_size - (len(processed_message) % block_size)
        processed_message += 'X' * padding_needed
    
    return processed_message

# --- Hill Cipher Core Functions ---

def cifrar_hill(message, key_matrix):
    """Encrypts a message using the Hill cipher."""
    n = len(key_matrix) # Dimension of the key matrix
    
    # Validate key matrix invertibility
    if n != 2:
        return "Error: Solo se admiten matrices clave de 2x2 para el cifrado."

    det = determinant_2x2(key_matrix) % ALPHABET_SIZE
    if math.gcd(det, ALPHABET_SIZE) != 1:
        return "Error: La clave no es invertible (determinante no coprimo con 26)."

    processed_message = prepare_message(message, n)
    
    ciphertext = []
    for i in range(0, len(processed_message), n):
        block_chars = processed_message[i : i + n]
        block_nums = [ALPHABET.find(char) for char in block_chars]
        
        # Encrypt block
        encrypted_block_nums = matrix_mult(key_matrix, block_nums, ALPHABET_SIZE)
        
        # Convert back to characters
        for num in encrypted_block_nums.flatten(): # .flatten() for numpy array to iterate elements
            ciphertext.append(ALPHABET[int(num)])
            
    return "".join(ciphertext)

def descifrar_hill(ciphertext, key_matrix):
    """Decrypts a message using the Hill cipher."""
    n = len(key_matrix) # Dimension of the key matrix

    if n != 2:
        return "Error: Solo se admiten matrices clave de 2x2 para el descifrado."

    # Calculate inverse key matrix
    inv_key_matrix = matrix_inverse_2x2(key_matrix, ALPHABET_SIZE)

    if inv_key_matrix is None:
        return "Error: La clave no es invertible (no se pudo calcular la inversa)."

    # Process ciphertext (no padding needed, just uppercase and alpha-only)
    processed_ciphertext = "".join(char for char in ciphertext.upper() if char.isalpha())

    if len(processed_ciphertext) % n != 0:
        return "Error: El texto cifrado tiene una longitud incorrecta para la clave dada."

    plaintext = []
    for i in range(0, len(processed_ciphertext), n):
        block_chars = processed_ciphertext[i : i + n]
        block_nums = [ALPHABET.find(char) for char in block_chars]
        
        # Decrypt block
        decrypted_block_nums = matrix_mult(inv_key_matrix, block_nums, ALPHABET_SIZE)
        
        # Convert back to characters
        for num in decrypted_block_nums.flatten():
            plaintext.append(ALPHABET[int(num)])
            
    return "".join(plaintext)

# --- Streamlit User Interface ---

st.set_page_config(page_title="Cifrador de Hill", layout="centered")

st.title("🔐 Cifrador de Hill")
st.subheader("(Cifrado por Bloques Matriz)")
st.markdown("---")
st.write("Script desarrollado por **Marcos Sebastian Cunioli** - Especialista en Ciberseguridad")
st.markdown("---")

# Key Matrix Input Section
st.header("Matriz Clave (2x2)")
st.info("""
    Ingrese su matriz clave de 2x2. Cada fila en una nueva línea, los números separados por espacios o comas.
    Ejemplo para una matriz [[3, 5], [4, 7]]:
    ```
    3 5
    4 7
    ```
    
    La clave debe ser invertible módulo 26. Esto significa que el determinante de la matriz debe ser coprimo con 26 (es decir, el MCD(determinante, 26) debe ser 1).
    """)

key_matrix_input = st.text_area(
    "Matriz Clave (ej. 3 5\\n4 7):",
    "3 5\n4 7", # Default 2x2 key
    height=80,
    key="key_matrix_input"
)

key_matrix = None
matrix_parse_error = None
if key_matrix_input:
    key_matrix, matrix_parse_error = parse_key_matrix(key_matrix_input)
    
    if matrix_parse_error:
        st.error(f"Error en la matriz clave: {matrix_parse_error}")
    elif key_matrix and len(key_matrix) != 2:
        st.error("Error: Actualmente solo se admiten matrices clave de 2x2.")
        key_matrix = None # Invalidate key_matrix if not 2x2
    elif key_matrix:
        try:
            det = determinant_2x2(key_matrix)
            det_mod = det % ALPHABET_SIZE
            if math.gcd(det_mod, ALPHABET_SIZE) != 1:
                st.error(f"Error: El determinante ({det_mod}) no es coprimo con 26. La clave no es invertible.")
                key_matrix = None # Invalidate key_matrix
            else:
                st.success(f"Matriz clave válida. Determinante mod 26: {det_mod}")
        except Exception as e:
            st.error(f"Error al validar la matriz: {e}")
            key_matrix = None


st.markdown("---")

# Encryption Section
st.header("Cifrar Mensaje")
message_to_encrypt = st.text_area("Ingrese el mensaje a cifrar:", height=100, key="encrypt_message")

if st.button("Cifrar Mensaje", key="btn_encrypt"):
    if message_to_encrypt and key_matrix is not None: # Ensure key_matrix is not None
        try:
            encrypted_text = cifrar_hill(message_to_encrypt, key_matrix)
            if "Error" in encrypted_text: # Check if the function returned an error string
                st.error(encrypted_text)
            else:
                st.success(f"**Texto cifrado:** `{encrypted_text}`")
                st.download_button(
                    label="Descargar Texto Cifrado",
                    data=encrypted_text,
                    file_name="mensaje_cifrado_hill.txt",
                    mime="text/plain"
                )
        except Exception as e:
            st.error(f"Error inesperado al cifrar: {e}. Asegúrese de que la clave sea válida y el mensaje contenga solo caracteres alfabéticos.")
    else:
        st.warning("Por favor, ingrese un mensaje y una matriz clave válida para cifrar.")

st.markdown("---")

# Decryption Section
st.header("Descifrar Mensaje")

decryption_option = st.radio(
    "¿Cómo desea descifrar el mensaje?",
    ("Ingresar texto cifrado directamente", "Cargar desde un archivo"),
    key="decryption_option"
)

st.info("Para descifrar, asegúrese de usar la misma 'Matriz Clave' que se usó para cifrar.")

if decryption_option == "Ingresar texto cifrado directamente":
    ciphertext_input = st.text_area("Ingrese el texto cifrado:", height=100, key="decrypt_input")
    
    if st.button("Descifrar Texto", key="btn_decrypt_input"):
        if ciphertext_input and key_matrix is not None: # Ensure key_matrix is not None
            try:
                decrypted_text = descifrar_hill(ciphertext_input, key_matrix)
                if "Error" in decrypted_text: # Check if the function returned an error string
                    st.error(decrypted_text)
                else:
                    st.info(f"**Texto descifrado:** `{decrypted_text}`")
            except Exception as e:
                st.error(f"Error inesperado al descifrar: {e}. Asegúrese de que la clave sea válida y el texto cifrado sea correcto.")
        else:
            st.warning("Por favor, ingrese el texto cifrado y una matriz clave válida para descifrar.")

elif decryption_option == "Cargar desde un archivo":
    uploaded_file = st.file_uploader("Cargue un archivo de texto (.txt) con el mensaje cifrado:", type="txt", key="file_uploader")
    
    if st.button("Descifrar Archivo", key="btn_decrypt_file"):
        if uploaded_file is not None and key_matrix is not None: # Ensure key_matrix is not None
            content_from_file = uploaded_file.read().decode("utf-8").strip()
            if content_from_file:
                try:
                    decrypted_text = descifrar_hill(content_from_file, key_matrix)
                    if "Error" in decrypted_text:
                        st.error(decrypted_text)
                    else:
                        st.info(f"**Texto descifrado desde archivo:** `{decrypted_text}`")
                except Exception as e:
                    st.error(f"Error inesperado al descifrar: {e}")
            else:
                st.error("El archivo cargado está vacío o no se pudo leer.")
        else:
            st.warning("Por favor, cargue un archivo y una matriz clave válida para descifrar.")

st.markdown("---")
st.markdown("Una herramienta de criptografía clásica para fines educativos y demostrativos.")
