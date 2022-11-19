import os
import datetime
import numbers

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    transactions_db = db.execute('''
        SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0
    ''', session["user_id"])

    # Creates a place to save the informations
    portfolio = []
    total = 0

    for data in transactions_db:
        stock = lookup(data['symbol'])
        values = (stock['price'] * data['shares'])
        portfolio.append({"symbol": stock["symbol"], "name": stock["name"], "shares": data["shares"], "price": usd(
            stock["price"]), "total": usd(values)})
        total += values

    # Information about money of users from database.
    money_db = db.execute('''
        SELECT cash FROM users WHERE id = ?
    ''', session["user_id"])
    cash = money_db[0]["cash"]
    total += cash
    return render_template('index.html', portfolio=portfolio, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template('buy.html')
    else:
        symbol = request.form.get('symbol').upper()
        # shares = int(request.form.get('shares'))

        # Ensure symbol was submitted
        if not symbol or symbol == ' ':
            return apology("Must give us a valid symbol")

        # Ensure username was submitted
        if not request.form.get('shares'):
            return apology("Must give us a valid shares (number data)")

        # if shares.isnumeric() == False:
        #     return apology("Must give us a integer data")

        # if isinstance(shares, int) == False:
        #     return apology("Enter a valid number")
        try:
            shares = int(request.form.get('shares'))
        except ValueError:
            return apology("Wrong shares data")

        if shares <= 0:
            return apology("Share not allowed")

        stock = lookup(symbol)
        # Check if stock is valid
        if stock == None:
            return apology('Symbol does not exist')

        transaction_value = shares * stock['price']
        userdb_cash = db.execute('''
            SELECT cash FROM users WHERE id = ?
        ''', session["user_id"])
        # return jsonify(userdb_cash)
        user_money = userdb_cash[0]["cash"]

        if user_money < transaction_value:
            return apology("User does not have enough money")

        # Subtract user_cash by value of transaction
        updt_cash = user_money - transaction_value

        db.execute('''
            UPDATE users SET cash = ? WHERE id = ?
        ''', updt_cash, session["user_id"])

        date = datetime.datetime.now()
        # Update de transactions table
        db.execute('''
            INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)
        ''', session["user_id"], stock['symbol'], shares, stock['price'], date)
        flash("Stonks💱💱")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('''
        SELECT * FROM transactions WHERE user_id = ?
    ''', session["user_id"])

    for i in range(len(history)):
        history[i]["price"] = usd(history[i]["price"])
    return render_template("history.html", history=history)


@app.route("/add_money", methods=["GET", "POST"])
@login_required
def add_money():
    """User can add cash"""
    if request.method == "GET":
        return render_template("add.html")
    else:
        new_cash = int(request.form.get('new_money'))

        if not new_cash or new_cash == ' ':
            return apology("Please user, enter an amount of money")

        if new_cash <= 0:
            return apology("Enter a valid number (greater than zero)")

        userdb_cash = db.execute('''
            SELECT cash FROM users WHERE id = ?
        ''', session["user_id"])
        # return jsonify(userdb_cash)
        user_money = userdb_cash[0]["cash"]

        updt_cash = user_money + new_cash

        db.execute('''
            UPDATE users SET cash = ? WHERE id = ?
        ''', updt_cash, session["user_id"])

        return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template('quote.html')
    else:
        symbol = request.form.get('symbol')

        # Ensure symbol was submitted
        if not symbol or symbol == ' ':
            return apology("Symbol is required")

        stock = lookup(symbol.upper())

        # Check if stock is valid
        if stock == None:
            return apology('Symbol does not exist')

        return render_template("quoted.html", stckF={'name': stock['symbol'], 'price': usd(stock['price'])})

# name = stock["name"], price = stock["price"], symbol = stock["symbol"]


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template('register.html')
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username or username == ' ':
            return apology("Must give us a valid username")
        # Ensure password was submitted
        if not password:
            return apology("Must give us password")
        # Ensure password was submitted
        if not confirmation:
            return apology("Must give us confirmation password")

        # both passwords must be equal
        if password != confirmation:
            return apology("Passwords no match")

        key_hash = generate_password_hash(password)
        try:
            new_user = db.execute('''
            INSERT INTO users(username, hash)
            VALUES (?, ?)
        ''', username, key_hash)
        except:
            return apology("Username already exists")

        # Redirect user to the homepage
        session["user_id"] = new_user

        return redirect('/')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        symbols_dat = db.execute('''
            SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0
        ''', session["user_id"])

        return render_template('sell.html', symbols=[symbol["symbol"] for symbol in symbols_dat])
    else:
        symbol = request.form.get('symbol').upper()
        shares = int(request.form.get('shares'))

        # Ensure symbol was submitted
        if not symbol:
            return apology("Please user, enter a valid symbol")

        # Ensure username was submitted
        if not shares:
            return apology("Must give us a valid shares (number data)")

        stock = lookup(symbol)
        # Check if stock is valid
        if stock == None:
            return apology('Symbol does not exist')

        if shares <= 0:
            return apology("Share not allowed, enter a valid number")

        transaction_value = shares * stock['price']
        userdb_cash = db.execute('''
            SELECT cash FROM users WHERE id = ?
        ''', session["user_id"])
        # return jsonify(userdb_cash)
        user_money = userdb_cash[0]["cash"]

        # Data from DB called transactions
        amount_shares = db.execute('''
            SELECT SUM(shares) AS shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol
        ''', session["user_id"], symbol)
        currently_stocks = amount_shares[0]["shares"]

        # Validation about amount of shares.
        if currently_stocks < shares:
            return apology("User does not have enough money")

        # Sum user_cash by value of transaction
        updt_cash = user_money + transaction_value

        db.execute('''
            UPDATE users SET cash = ? WHERE id = ?
        ''', updt_cash, session["user_id"])

        date = datetime.datetime.now()
        # Update de transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (:user_id, :symbol, :shares, :price, :date)",
                   user_id=session["user_id"], symbol=stock['symbol'], shares=-1 * shares, price=stock['price'], date=date)
        flash("Sold!💱💱")
        return redirect("/")
