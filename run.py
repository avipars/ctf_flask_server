from ctf import app

print("Running Flask Server")

if __name__ == "__main__":
    # app.run(debug=True, port="5000") #debug ,
    # host="colaco.website",
    app.run(debug=False, port=8080)  # production
