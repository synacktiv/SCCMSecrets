def check_principal_format(principal_str: str):
    principal, realm = principal_str.split('@')
    return True if realm else False
