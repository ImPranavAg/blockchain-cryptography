from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public = private.public_key()
    return private, public


# Converting Message To Bytes!
def sign(message, private):
    message = bytes(str(message), "utf-8")

    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    return signature


def verify(message, sig, public):
    message = bytes(str(message), "utf-8")

    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing Public key!")
        return False


if __name__ == "__main__":

    # Brother A
    pr, pu = generate_keys()
    # print(pr)
    # print(pu)

    message = "Hey! I am learning Blockchain."

    sig = sign(message, pr)
    # print(sig)

    correctness = verify(message, sig, pu)
    if correctness:
        print("Successful!!")
    else:
        print("Failed.")

    # Idhar apan B ki public key se A ki private key ko access kr rhe hai
    # Brother B
    prB, puB = generate_keys()
    correctness = verify(message, sig, puB)
    if correctness:
        print("Successful!!")
    else:
        print("Failed.")
