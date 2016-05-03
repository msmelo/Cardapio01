var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt');

var CompanySchema = new Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  cnpj:{
    type: String,
    required: true,
    unique: true
  },
  email:{
    type: String,
    required: true,
    unique: true
  },
  password: {
    type : String,
    required: true
  },
  phone:{
    type: String,
    required: true,
    unique: true
  },
  address:{
    zipCode: {type: String},
    street: {type: String},
    number: {type: Number},
    neighborhood: {type: String},
    city: {type: String},
    state : {type: String}
  },
  social:{
    facebook:{type: String},
    instagram:{type: String}
  },
  accessToken:{
    type: String
  },
  create_at:{
    type: Date,
    default: Date.now
  },
  update_at:{
    type: Date,
    default: Date.now
  }
});

CompanySchema.pre('save', function (next) {
    var company = this;
    if (this.isModified('password') || this.isNew) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcrypt.hash(company.password, salt, function (err, hash) {
                if (err) {
                    return next(err);
                }
                company.password = hash;
                next();
            });
        });
    } else {
        return next();
    }
});

CompanySchema.pre('findOneAndUpdate', function (next){
    var company = this._update;
    if (company.password !== undefined) {
        bcrypt.genSalt(10, function (err, salt) {
            if (err) {
                return next(err);
            }
            bcrypt.hash(company.password, salt, function (err, hash) {
                if (err) {
                    return next(err);
                }
                company.password = hash;
                company.update_at= Date.now();
                next();
            });
        });
    }else{
      company.update_at= Date.now();
      next();
    }
});

CompanySchema.methods.comparePassword = function (passw, cb) {
    bcrypt.compare(passw, this.password, function (err, isMatch) {
        if (err) {
            return cb(err);
        }
        cb(null, isMatch);
    });
};


module.exports = mongoose.model('Company', CompanySchema);
