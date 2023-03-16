require("dotenv").config()
const User = require("./User.js")
const RefreshToken = require("./refreshToken.js")
const validateRequest = require("./validateRequest.js")

const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cors = require("cors")
const express = require("express")
const { compareSync } = require("bcrypt")
//APP CONFIG
const port = process.env.PORT || 4000
const app = express()
app.use(express.json())
app.use(cors({
    allowedHeaders:["Content-Type","authorization"],
    origin: "*",
    methods:["PATCH","POST"],
}))

//ROUTING
app.get("/test", (req, res) =>{
    res.json({data:"hello"})
})
app.post("/register", ( req , res ) => {
    //Recieves an username and a password in the body of the post request
    const { username , password } = req.body
    // If the username or password are missing returns and error
	if (!username || !password  ) return res.sendStatus(400)
    //If the username and password are valid, checks the database to see if the username already exists
	User.findOne({username:username} , ( err , user ) => {
		if ( err ) return res.sendStatus(500)
		if ( user ) return res.sendStatus(409)
        //If the username does not exists, creates a hash of the password, 
        //and then creates a new user object in the db, with the username and the hash
		bcrypt.hash( password , 10 , ( err , hash ) => {
			if( err ) return res.sendStatus(500)
			const newUser = new User({
				username : username,
				password : hash,
			})
			newUser.save( ( err ) => {
				if ( err ) res.send(500)
				else res.sendStatus(201)
			}) 
		})
	})  

})

app.post("/login", ( req , res ) => {
    console.log(req.body)
    //Receives an username and a password in the request body
    const { username , password } = req.body
    //Checks if any of the credentials are missing
    if ( !username || !password ) return res.send(400)
    //If both username and password are valid, checks if the username exists on the db
	User.findOne( {username:username} , (err, user) => {
		if ( !user ) return res.sendStatus(404)
        if ( err ) return res.send(500)
        //If the user exists, the received password is hashed and then compared with the hash stored in the db
		bcrypt.compare( password , user.password , ( err , result ) => {
            if ( err ) return res.send(500)
            if ( !result ) return res.send(401)
            const accessToken = jwt.sign({_id:user._id,username:user.username,},process.env.JWT_SECRET,{expiresIn:"10s"})
            const refreshToken = jwt.sign({_id:user._id,username:user.username}, process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"})
            const newRefreshToken = new RefreshToken({
                userId : user._id,
                token : refreshToken
            })
            newRefreshToken.save( err => {
                if ( err ) return res.sendStatus(500)
               res.json({
                    accessToken : accessToken,
                    refreshToken : refreshToken,
                    userId : user._id
                })
            })
        })
	})
})


app.post("/logout", validateRequest , ( req , res ) => {
    const { _id } = req.token
    RefreshToken.deleteMany({userId : _id} , ( err ) => {
        if ( err ) return res.send(err)
        res.send(200)
    })
})


app.post("/refreshToken" , ( req , res ) => {
    const token = req.body.token
    if ( !token ) return res.send(401)
    jwt.verify( token , process.env.REFRESH_TOKEN_SECRET , ( err , decoded ) => {
        if ( err ) return res.sendStatus(403)
        RefreshToken.findOne({userId:decoded._id, token:token}, ( err , foundToken ) => {
            if ( err ) return res.sendStatus(500)
            if ( !foundToken   ) return res.sendStatus(403)
            const accessToken = jwt.sign({_id:decoded._id,username:decoded.username,},process.env.JWT_SECRET,{expiresIn:"30s"})
            res.json({accessToken:accessToken})
        })
   })
})
app.post("/validateToken" , ( req , res ) => {
    const {token} = req.body
    if ( !token ) return res.sendStatus(401)
    jwt.verify(token, process.env.JWT_SECRET, ( err , decoded ) => {
        if ( err ) return res.sendStatus(403)
        res.sendStatus(200)
    })
})



app.patch("/users/follow/:userId", validateRequest ,  ( req , res ) => {
    console.log(req.user)
    const userFollowing = req.user._id
    if ( req.params.userId === userFollowing ) return res.sendStatus(400)
    User.findOne({_id:req.params.userId} , ( err , userToFollow ) => {
        if ( err ) return res.sendStatus(500)
        if ( !userToFollow ) return res.sendStatus(404)
        if ( userToFollow.followers.includes( userFollowing) ) {

            // Removing the current user from the followers of user being followed
            userToFollow.followers.splice(userToFollow.followers.indexOf(userFollowing))
            userToFollow.save()
            //Removing the user being followed from the following of the current user
            User.findOne({_id:userFollowing} , ( err , user ) => {
                console.log(err)
                if ( err ) res.sendStatus(500)
                user.following.splice(user.following.indexOf( userToFollow._id))
                user.save( err => {

                    if ( err ) return res.sendStatus(500)
                    return res.sendStatus(200)
                })
            })
        } else {
            // Adding the current user to the followers of user being followed
            userToFollow.followers.push( userFollowing) 
            userToFollow.save()
            //Adding the user being followed to the following of the current user
            User.findOne({_id:userFollowing} , ( err , user ) => {

                console.log(err)
                user.following.push( userToFollow._id ) 
                user.save(err => {
                    if ( err )return res.sendStatus( 500 ) 
                    return res.sendStatus(200)
                })
            })
        }
    })
})

app.get("/userInfo/:userId" , ( req , res ) => {
    const {userId} = req.params
    const token = req.headers.authorization
    if ( !userId ) return res.sendStatus(400)
    User.findOne({_id: userId}, ( err , user ) => {
        if ( !user ) return res.sendStatus(404)
        if ( err ) return res.sendStatus(500)
        jwt.verify(  token , process.env.JWT_SECRET , ( err , decoded ) => {
            //Data that should be returned if the requesting user is not logged.
            if ( err ) {
                return res.json({
                    username:user.username,
                    descritption: user.descritption,
                    followers : user.followers,
                    following : user.following,
                    sameUser : false,
                    isFollowing : false
                })
            }
            //Data that should be returned if the requesting user and the requested user are the same
            if ( decoded._id === user.id ) {
                return res.json({
                    username:user.username,
                    descritption: user.descritption,
                    followers : user.followers,
                    following : user.following,
                    sameUser : true,
                    isFollowing : false
                })
            }
            //Data that should be returned if the requesting user is logged but is not the same as the requested user
            if ( decoded && decoded._id != user.id ) {
                return res.json({
                    username:user.username,
                    descritption: user.descritption,
                    followers : user.followers,
                    following : user.following,
                    sameUser : false ,
                    //Check if the requesting user is following the requested one
                    isFollowing :  user.followers.includes(decoded._id)
                })
            }
        })
    })
})

app.listen(port , () => console.log("auth server running on port: " + port.toString()))