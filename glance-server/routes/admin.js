const {Router}=require('express')
const adminrouter = Router();
adminrouter.get('/test',(req,res,next)=>{
    res.json({message:"test"})
})
module.exports=adminrouter;
