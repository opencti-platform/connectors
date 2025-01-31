def dict_to_serialized_list(data: dict) -> str:
    """
    Convert a dict to a stringified list of key/value pairs.
    :param data: Dict to convert
    :return: Stringified list
    """
    serialized_items = [f"{key} = {data[key]}" for key in data]

    return ", ".join(serialized_items)


def dict_to_markdown_table(data: dict) -> str:
    """
    Convert a dict to a key/value Markdown table.
    :param data: Dict to build Markdown table from
    :return: String representing the Markdown table
    """
    markdown_table = "| Field | Value |  \n"
    markdown_table += "| ---- | ----- |  \n"

    for key in data:
        markdown_table += f"| {key} | {data[key]} |  \n"

    return markdown_table
