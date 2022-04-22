const mongoose = require("mongoose")
mongoose.connect(process.env.DATA_BASE_URL)

const userSchema = {
    username : String,
    password : String,
    description : String,
    followers : [String],
    following : [String]
}
const User = mongoose.model("User" , userSchema)

module.exports = User