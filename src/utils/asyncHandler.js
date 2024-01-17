const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        Promise
            .resolve(requestHandler(req, res, next))
            .catch((error) => next(error))
    }
}

export { asyncHandler }


// usig try catch
// const asyncHandler2 = (func) => async (req, res, next) => {
//     try {
//         await func(req, res, next);
//     } catch (error) {
//         res.status(res.code || 500).json({
//             success: false,
//             message: error.message

//         })
//     }
// }