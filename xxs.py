from flask import Flask, request, render_template_string

app = Flask(__name__)

# We'll just store comments in a list in memory for this example
comments = []

# The HTML template. 
# The vulnerability is rendering {{ comment }} without escaping.
# In Jinja2 (Flask's template engine), |safe tells it "this is safe, don't escape it."
PAGE_TEMPLATE = """
<html>
    <body>
        <h2>Leave a comment:</h2>
        <form method="POST" action="/">
            <input type="text" name="comment_text" size="50">
            <input type="submit" value="Submit">
        </form>
        
        <hr>
        
        <h2>Comments:</h2>
        {% for comment in comments %}
            <div>{{ comment | safe }}</div> {% endfor %}
    </body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def comment_wall():
    if request.method == 'POST':
        # Get comment from the form and store it
        new_comment = request.form.get('comment_text')
        if new_comment:
            comments.append(new_comment)
    
    # Render the page, passing in the list of comments
    return render_template_string(PAGE_TEMPLATE, comments=comments)

if __name__ == '__main__':
    print("WARNING: Running a VULNERABLE application.")
    print("Open http://127.0.0.1:5000 in your browser.")
    print("Try submitting a normal comment, then submit: <script>alert('XSS Attack!');</script>")
    app.run(debug=False)
