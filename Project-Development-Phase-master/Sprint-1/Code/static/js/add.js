// 
function required()
{
var empt = document.forms["add"]["date"].value;
var empt1 = document.forms["add"]["expensename"].value;
var empt2 = document.forms["add"]["amount"].value;
var empt3 = document.forms["add"]["paymode"].value;
var empt4 = document.forms["add"]["category"].value;
if (empt == "")
{
alert("Please add the date");
event.preventDefault();
return false;
}
else if(empt1== "")
{
    alert("Please add the expensename");
    event.preventDefault();
    return false;
    }
else if(empt2== "")
{
    alert("Please selet the amount");
    event.preventDefault();
    return false;
    }
else if(empt3== "")
{
    alert("Please select the paymode");
    event.preventDefault();
    return false;
    }
else if(empt4== "")
{
    alert("Please select the category");
    event.preventDefault();

    return false;
    }
else 
{

return true; 
}
}