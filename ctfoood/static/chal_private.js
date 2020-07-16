let mp = document.getElementById('make_public');
let ad = document.getElementById('as_default');
let dh = document.getElementById('dockerhub');
let adl = document.getElementById('as_default_label');
let dhl = document.getElementById('dockerhub_label');

function changed_dockerhub(e)
{
    if (dh.checked) {
        ad.disabled = false;
        adl.style.color = '';
    } else {
        ad.checked = false;
        ad.disabled = true;
        adl.style.color = '#777';
    }
}

function changed_public(e)
{
    if (mp.checked) {
        dh.disabled = false;
        dhl.style.color = '';
    } else {
        dh.checked = false;
        dh.disabled = true;
        dhl.style.color = '#777';
    }
    changed_dockerhub(dh);
}

mp.onchange = changed_public;
dh.onchange = changed_dockerhub;

changed_public();
