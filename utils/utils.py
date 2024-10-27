def encode_UTF16_strip_BOM(data):
    return data.encode('utf-16')[2:]

def clean_junk_in_XML(xml_string):
    root_end = xml_string.rfind('</')
    if root_end != -1:
        root_end = xml_string.find('>', root_end) + 1
        clean_xml_string = xml_string[:root_end]
        return clean_xml_string
    return xml_string
