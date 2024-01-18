class ApiError extends Error {
    constructor(
        statusCode,
        message = "Something went wrong",
        errors = [],
        stack = ""
    ) {
        super(message);
        this.statusCode = statusCode;
        this.data = null;
        this.message = message;
        this.success = false;
        this.errors = errors;

        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructer);
        }
    }
}

const throwError = (condition, statusCode, message) => {
    if (condition) {
        throw new ApiError(statusCode, message);
    }
};

export default ApiError;
export { throwError };
