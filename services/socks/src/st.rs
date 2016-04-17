pub static INDEX: &'static str = "
<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">
<html {% block htmlsuffix %}{% endblock %}>
<html>
<head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">
<title>Socks!</title>

  <script type=\"text/javascript\" src=\"https://yastatic.net/jquery/2.2.0/jquery.min.js\"></script>

<!-- Latest compiled and minified CSS -->
<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">

<!-- Optional theme -->
<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap-theme.min.css\" integrity=\"sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r\" crossorigin=\"anonymous\">

<!-- Latest compiled and minified JavaScript -->
<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js\" integrity=\"sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS\" crossorigin=\"anonymous\"></script>

  <!-- <script type=\"text/javascript\" src=\"http://malsup.github.io/jquery.form.js\"></script> -->
  <!-- <script type=\"text/javascript\" src=\"{{ STATIC_URL }}jquery-metadata/jquery.metadata.js\"></script> -->



    <style type=\"text/css\">
      body {
      }

      .table .no-font-weight {
        font-weight: normal;
        white-space: nowrap;
        background-color: white;
      }

      .header_sortable {
        cursor: pointer;
      }

      .sidebar-nav {
        padding: 9px 0;
      }

      table {
        //table-layout: fixed;
      }

      .fixedsticky { top: 120px; }

    </style>
</head>
<body data-spy=\"scroll\">
<nav class=\"navbar navbar-default\">
  <div class=\"container-fluid\">
    <!-- Brand and toggle get grouped for better mobile display -->
    <div class=\"navbar-header\">
      <button type=\"button\" class=\"navbar-toggle collapsed\" data-toggle=\"collapse\" data-target=\"#bs-example-navbar-collapse-1\" aria-expanded=\"false\">
        <span class=\"sr-only\">Toggle navigation</span>
      </button>
      <a class=\"navbar-brand\" href=\"/\">Socks</a>
    </div>

    <!-- Collect the nav links, forms, and other content for toggling -->
  </div><!-- /.container-fluid -->
</nav>

<div class=\"container\">

<div class=\"jumbotron\">
  <img src=\"http://usu.edu.ru/socks.png\"></img>
  <!-- <h1>Socks!</h1> -->
  <p>Find where you put your things</p>
  <!-- <p><a class=\"btn btn-primary btn-lg\" href=\"#\" role=\"button\">Learn more</a></p> -->
</div>

<form class=\"navbar-form navbar-left\" role=\"search\" action=\"/search\">
  <div class=\"form-group\">
    <input type=\"text\" class=\"form-control\" placeholder=\"Thing\" size=\"100\" name=\"text\">
    <input type=\"text\" class=\"form-control\" placeholder=\"Access code\" name=\"owner\">
  </div>
  <button type=\"submit\" class=\"btn btn-default\">Submit</button>
</form>

</div>
</body>
</html>
";
