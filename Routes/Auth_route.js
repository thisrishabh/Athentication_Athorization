const express=require('express')
const router=express.Router()
const User=require('../models/User_model')
const createError=require('http-errors')
const {authSchema}=require('../helpers/validation_schema')
const {signAccessToken,signRefreshToken,verifyRefreshToken}=require('../helpers/jwt_helper')

const blacklistedTokens = new Set();

router.post('/register',async(req,res,next)=>{
    try{
        //const {email,password}=req.body
        //if(!email || !password) throw createHttpError.BadRequest()
        const result=await authSchema.validateAsync(req.body)

        const doesExist= await User.findOne({email:result.email})
        if(doesExist) throw createError.Conflict(result.email+ ' is already registed.')

        const user=new User(result)
        const savedUser=await user.save()
        const accessToken=await signAccessToken(savedUser.id)
        const refreshToken=await signRefreshToken(savedUser.id)
        res.json({accessToken,refreshToken})

    }catch(err){
        if(err.isJoi===true) err.status=422
        next(err)
    }

})

router.post('/login',async(req,res,next)=>{
    try {
        
        const result = await authSchema.validateAsync(req.body)
        const user=await User.findOne({email:result.email})
        if(!user) throw createError.NotFound('User not registered')
        
        const isMatch= await user.isValidPassword(result.password)
        if (!isMatch) throw createError.Unauthorized('Username/Password not valid')
        
        const accessToken=await signAccessToken(user.id)
        const refreshToken=await signRefreshToken(user.id)
        blacklistedTokens.delete(user.id);
        res.json({accessToken,refreshToken})
    } catch (error) {
        if(error.isJoi==true) 
            return next(createError.BadRequest('Invalid Username/Password'))
        next(error)
    }
})

router.post('/refresh-token',async(req,res,next)=>{
    try {
        const {refreshToken}=req.body
        
        if(!refreshToken) throw createError.BadRequest()
        const userId = await verifyRefreshToken(refreshToken)
        console.log("refrsh", userId)
        const accessToken=await signAccessToken(userId)
        const refToken= await signRefreshToken(userId)
        res.send({accessToken:accessToken,refreshToken:refToken})
    } catch (error) {
        next(error)
    }
})


router.delete('/logout',async(req,res,next)=>{
    try {
        const {refreshToken}=req.body
        console.log(refreshToken)
        if(!refreshToken) throw createError.BadRequest()
         const userId = await verifyRefreshToken(refreshToken)
        console.log(userId)
         if (blacklistedTokens.has(userId)) {
            res.json({ message: 'Refresh token is blacklisted' });
          }else{
          blacklistedTokens.add(userId);
          res.json({message:'you logout sucessfuly'})
          }
          
          

    } catch (error) {
        next(error)
    }
})


module.exports=router