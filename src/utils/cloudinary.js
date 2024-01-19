import fs from "fs"
import { v2 as cloudinary } from 'cloudinary';

cloudinary.config({
    cloud_name: 'instacloneclouddheer',
    api_key: '487523472717783',
    api_secret: 'uGm79HwfIxG9rfNPV3eU8DmHBTg'
});


const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null
        //upload the file on cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        // file has been uploaded successfull
        //console.log("file is uploaded on cloudinary ", response.url);
        fs.unlinkSync(localFilePath)
        return response;
    } catch (error) {
        console.log("Error in upload on cloudinary: ", error)
        fs.unlinkSync(localFilePath) // remove the locally saved temporary file as the upload operation got failed
        return null;
    }
}



export { uploadOnCloudinary }