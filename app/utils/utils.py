def format_file_size(size_in_bytes):
    """
    Convert file size in bytes to a human-readable format.
    :param size_in_bytes: File size in bytes
    :return: Formatted string with appropriate size unit
    """
    if size_in_bytes == 0:
        return "0B"

    size_units = ["B", "KB", "MB", "GB", "TB"]
    index = 0

    while size_in_bytes >= 1024 and index < len(size_units) - 1:
        size_in_bytes /= 1024.0
        index += 1

    # Keep only two decimal places
    return f"{size_in_bytes:.2f} {size_units[index]}"
