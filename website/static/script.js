// typed below


// document.getElementById("account_circle").addEventListener("click", function () {
//     var account = document.getElementById("dropdown");
//     account.style.display = 'none'
// })

function increment(icon) {
    var input_container = icon.parentNode;
    var item_no = input_container.querySelector('.item_no');
    item_no.stepUp();
    checkMaxMin();
};

function decrement(icon) {
    var input_container = icon.parentNode;
    var item_no = input_container.querySelector('.item_no');
    item_no.stepDown();
    checkMaxMin();
};

$(document).ready(function() {
    $('.dropdown').hide()

    function remove() {
        $('.error').hide()
    };

    $('.account_circle').click(function () {
        $('#dropdown').toggle();         
    })

    

    // document.getElementById("contact-button").addEventListener("click", function(){
    //     document.getElementsByClassName("popup")[0].classList.add("active");
    // })

    // typed below

})


// in Jquery, 

// semicolon present

// jquery not working

