function copy_element_text_by_id(element_id) {
    var text = document.getElementById(element_id);
    navigator.clipboard.writeText(text.innerText);
}

function download_element_text_as_file_by_id(element_id) {
    var text = document.getElementById(element_id);
    download_text_as_file(text.innerText, "ballotbox_token.txt")
}

function download_text_as_file(text, filename) {
    var element = document.createElement("a");
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}
