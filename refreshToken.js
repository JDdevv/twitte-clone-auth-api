const mongoose = require("mongoose")
mongoose.connect(process.env.DATA_BASE_URL)

const refreshTokenSchema = {
    userId: String,
    token : String
}
const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema)
module.exports = RefreshToken