import mongoose from 'mongoose';

const signInEventSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    signedInAt: {
      type: Date,
      default: Date.now,
      required: true,
    },
  },
  { versionKey: false },
);

const SignInEvent = mongoose.model('SignInEvent', signInEventSchema);

export default SignInEvent;
