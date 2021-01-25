function find_parent_form(el)
{
    while (el) {
        el = el.parentNode;
        if (el.tagName.toLowerCase() == "form")
            return el;
    }
}

//function submit_my_form(el)
//{
//    let f = find_parent_form(el);
//    f.reportValidity();
//    if (f.checkValidity())
//        f.submit();
//}

function recaptcha_register_submit(token)
{
    let f = document.getElementById("register_form");
    f.reportValidity();
    if (f.checkValidity())
        f.submit();
}

function show_vm_msg(m) {
    let s = document.getElementById('vm_message');
    s.innerText = m;
    s.classList.toggle('faded');
    if (m.includes('inished')) {
        clearInterval(vmstatus_interval_id);
        s.style.color = 'gray';
        s.classList.remove('faded');
        document.getElementById('vm_ip').classList.add("vm_ip_finished");
    }
}

function vm_spawn_error(e) { show_vm_msg("ERROR"); }
function vm_spawned(e) {
    show_vm_msg("Spawned!");
    let r = this.responseText.split(",");
    vmid = r[0];
    vmuuid = r[1];
    update_vm_status();
    vmstatus_interval_id = setInterval(update_vm_status, 2000);
}
function vm_status_update(e) {
    let r = this.responseText.split(",");
    let vmip = r[0];
    let vmport = r[1];
    let msg = r.slice(2).join(',');
    show_vm_msg(msg);
    if (vmip) {
        document.getElementById('vm_ip').innerText = vmip + ":" + vmport;
        l = document.getElementById('run_test_deployed');
        if (!l.href.endsWith("/" + vmid)) {  // This function is called periodically
            l.href = l.href + "/" + vmid;
            l.style.display = "inline";
        }
    }
}

function update_vm_status()
{
    let d = new FormData();
    d.append('vmid', vmid)
    d.append('vmuuid', vmuuid)

    let xhr = new XMLHttpRequest();
    xhr.addEventListener("error", vm_spawn_error);
    xhr.addEventListener("abort", vm_spawn_error);
    xhr.addEventListener("load", vm_status_update);
    xhr.open("POST", '/get_vm_status');
    xhr.setRequestHeader("X-CSRFToken", document.getElementsByName('csrfmiddlewaretoken')[0].value);
    xhr.send(d);
}



function plain_ooo_submit(e) { e.preventDefault(); recaptcha_ooo_submit(""); }
function recaptcha_ooo_submit(token)
{
    let f = document.getElementById("spawn_on_ooo_form");
    f.reportValidity();
    if (!f.checkValidity())
        return;

    document.getElementById('ooo_submit_button').hidden = true;
    show_vm_msg("Preparing the request...");

    let d = new FormData();
    d.append('ooo_allowed_ip', document.getElementsByName('ooo_allowed_ip')[0].value);
    if (document.getElementsByName('i_will_be_good')[0].checked)
        d.append('i_will_be_good', document.getElementsByName('i_will_be_good')[0].checked)
    if (document.getElementsByName('i_am_opting_in_for_data_collection')[0].checked)
        d.append('i_am_opting_in_for_data_collection', document.getElementsByName('i_am_opting_in_for_data_collection')[0].checked)
    d.append('g-recaptcha-response', token);

    let xhr = new XMLHttpRequest();
    xhr.addEventListener("error", vm_spawn_error);
    xhr.addEventListener("abort", vm_spawn_error);
    xhr.addEventListener("load", vm_spawned);
    xhr.open("POST", f.action);
    xhr.setRequestHeader("X-CSRFToken", document.getElementsByName('csrfmiddlewaretoken')[0].value);
    xhr.send(d);

    show_vm_msg("Request sent...");
}

function delete_vm_click(e) {
    e.preventDefault();

    btn = e.target;
    btn.value = "deleting...";
    btn.disabled = true;

    let f = find_parent_form(btn);

    let xhr = new XMLHttpRequest();
    //xhr.addEventListener("error", vm_spawn_error);
    //xhr.addEventListener("abort", vm_spawn_error);
    //xhr.addEventListener("load", vm_spawned);
    xhr.open("POST", f.action);
    xhr.setRequestHeader("X-CSRFToken", document.getElementsByName('csrfmiddlewaretoken')[0].value);
    xhr.send();

    console.log("Sent delete_vm request: ", f.action);
    return false;
}
