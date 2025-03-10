import subprocess
import platform


def verify_digital_signature(file_path):
    """
    Verifies the digital signature of a file using the Windows Signtool.
    This method assumes Signtool is installed and available in the PATH.
    Returns a dictionary with the verification result.
    """
    if platform.system() != "Windows":
        return {
            "file": file_path,
            "signature_valid": False,
            "error": "Digital signature verification is only supported on Windows."
        }

    try:
        result = subprocess.run(
            ["signtool", "verify", "/pa", file_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
        if "Successfully" in output:
            return {
                "file": file_path,
                "signature_valid": True,
                "output": output.strip()
            }
        else:
            return {
                "file": file_path,
                "signature_valid": False,
                "output": output.strip()
            }
    except Exception as e:
        return {
            "file": file_path,
            "signature_valid": False,
            "error": str(e)
        }
