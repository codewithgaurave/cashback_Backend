const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name'],
    },
    phone: {
      type: String,
      required: [true, 'Please add a phone number'],
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      trim: true,
      lowercase: true,
    },
    firmName: {
      type: String,
    },
    profileImage: {
      type: String,
      default: '',
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: 6,
    },
    role: {
      type: String,
      enum: ['admin', 'sub-admin', 'retailer', 'electrician'],
      default: 'electrician',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    kycStatus: {
      aadhar: {
        type: String,
        enum: ['pending', 'submitted', 'approved', 'rejected'],
        default: 'pending',
      },
      pan: {
        type: String,
        enum: ['pending', 'submitted', 'approved', 'rejected'],
        default: 'pending',
      },
    },
    kycDetails: {
      aadharNumber: { type: String },
      aadharFrontUrl: { type: String },
      aadharBackUrl: { type: String },
      panNumber: { type: String },
      panCardUrl: { type: String },
      rejectionReason: { type: String, default: '' },
    },
    shopDetails: {
      shopName: { type: String },
      shopAddress: { type: String },
      gstNumber: { type: String },
    },
    bankDetails: {
      accountHolderName: { type: String },
      accountNumber: { type: String },
      ifscCode: { type: String },
      bankName: { type: String },
      passbookChequeUrl: { type: String, default: '' },
    },
    salesPerson: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SalesPerson',
    },
    salesCode: {
      type: String,
      trim: true,
      uppercase: true,
      default: '',
    },
    customUserId: {
      type: String,
      trim: true,
      uppercase: true,
      sparse: true,
    },
    fcmToken: {
      type: String,
      default: '',
    },
    resetPasswordOTP: {
      type: String,
    },
    resetPasswordOTPExpire: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Helper to generate next sequential user ID (EL1001 for electrician, RT1001 for retailer)
UserSchema.statics.generateNextUserId = async function (role) {
  const prefix = role === 'retailer' ? 'RT' : 'EL';
  const regex = new RegExp(`^${prefix}(\\d+)$`);
  const existingUsers = await this.find(
    { customUserId: { $regex: `^${prefix}\\d+` } },
    'customUserId'
  ).lean();

  let maxNum = 1000;
  for (const u of existingUsers) {
    if (u.customUserId) {
      const match = u.customUserId.match(regex);
      if (match) {
        const num = parseInt(match[1], 10);
        if (!isNaN(num) && num > maxNum) {
          maxNum = num;
        }
      }
    }
  }
  return `${prefix}${maxNum + 1}`;
};

// Helper to ensure existing users have customUserId assigned
UserSchema.statics.ensureUsersHaveCustomId = async function () {
  try {
    const usersWithoutId = await this.find({
      $or: [{ customUserId: { $exists: false } }, { customUserId: null }, { customUserId: '' }],
    }).sort({ createdAt: 1 });

    for (const u of usersWithoutId) {
      const targetRole = u.role === 'retailer' ? 'retailer' : 'electrician';
      const nextId = await this.generateNextUserId(targetRole);
      await this.updateOne({ _id: u._id }, { $set: { customUserId: nextId } });
    }
  } catch (err) {
    console.error('ensureUsersHaveCustomId error:', err);
  }
};

// Pre-save hook: Auto-generate customUserId and encrypt password
UserSchema.pre('save', async function () {
  if (!this.customUserId && (this.role === 'electrician' || this.role === 'retailer')) {
    this.customUserId = await this.constructor.generateNextUserId(this.role);
  }

  if (!this.isModified('password')) {
    return;
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Compare user password
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
