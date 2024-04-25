// Importing required modules
import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import serviceAccountKey from "./sp-blogging-website-firebase-adminsdk-xmx7l-3b2931fdd2.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";

// Importing schemas
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";

// Initializing the Express server and setting the port number
const server = express();
let PORT = 3000;

// Initializing Firebase admin SDK with service account credentials
admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

// Regex expressions for email and password validation
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

// Middleware for parsing JSON
server.use(express.json());

// Middleware for enabling Cross-Origin Resource Sharing
server.use(cors());

// Connecting to MongoDB database
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

// Setting up AWS S3 bucket configuration
const s3 = new aws.S3({
  region: "ap-south-1",
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// Function to generate a signed URL for uploading an image to AWS S3 bucket
const generateUploadURL = async () => {
  try {
    const date = new Date();
    const imgName = `${nanoid()}-${date.getTime()}.jpeg`;

    const signedURL = await s3.getSignedUrlPromise("putObject", {
      Bucket: "sp-reactjs-blogging-website",
      Key: imgName,
      Expires: 1000,
      ContentType: "image/jpeg",
    });

    return signedURL;
  } catch (err) {
    console.error("Error generating upload URL:", err);
    throw err;
  }
};

// Middleware to verify JSON Web Token (JWT) for authentication
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(400).json({ error: "No access token" });
  }

  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      if (err.name == "JsonWebTokenError") {
        return res.status(401).json({ error: "Invalid access token" });
      } else if (err.name == "TokenExpiredError") {
        return res.status(401).json({ error: "Access token expired" });
      } else {
        return res.status(500).json({ error: "Internal server error" });
      }
    }
    req.user = user.id;
    next();
  });
};

// Function to format user data before sending
const formatDataToSend = (user) => {
  try {
    const access_token = jwt.sign(
      { id: user._id },
      process.env.SECRET_ACCESS_KEY
    );

    return {
      access_token,
      profile_img: user.personal_info.profile_img,
      username: user.personal_info.username,
      fullname: user.personal_info.fullname,
    };
  } catch (err) {
    console.error("Error formatting data to send:", err);
    throw err;
  }
};

// Function to generate a unique username based on the user's email
const generateUsername = async (email) => {
  try {
    let username = email.split("@")[0];

    const isUsernameNotUnique = await User.exists({
      "personal_info.username": username,
    });

    isUsernameNotUnique ? (username += nanoid().substring(0, 5)) : "";

    return username;
  } catch (error) {
    console.error("Error generating username:", error);
    throw new Error("Failed to generate username");
  }
};

// Endpoint to retrieve a signed URL for uploading images
server.get("/get-upload-url", async (req, res) => {
  await generateUploadURL()
    .then((url) => res.status(200).json({ uploadURL: url }))
    .catch((err) => {
      console.error("Error generating upload URL:", err);
      return res.status(500).json({ error: "Failed to generate upload URL" });
    });
});

// Endpoint for user sign up
server.post("/signup", async (req, res) => {
  let { fullname, email, password } = req.body;

  // Validating the data from frontend
  if (!fullname || fullname.length < 3) {
    return res
      .status(400)
      .json({ error: "Full name must be at least 3 letters long." });
  }

  if (!email.length) {
    return res.status(400).json({ error: "Email is required." });
  }
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid Email" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, one lowercase and one uppercase letters",
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    const username = await generateUsername(email);

    const user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    await user
      .save()
      .then((u) => {
        return res.status(200).json(formatDataToSend(u));
      })
      .catch((err) => {
        if (err.code == 11000) {
          return res.status(500).json({ error: "Email already exists" });
        }

        console.error("Error signing up user:", err);
        return res.status(500).json({ error: "Failed to sign up user" });
      });
  });
});

// Endpoint for user sign in
server.post("/signin", async (req, res) => {
  let { email, password } = req.body;

  await User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(500).json({
              error: "An error occurred while signing in.",
            });
          }

          if (!result) {
            return res.status(403).json({ error: "Incorrect Password!" });
          } else {
            return res.status(200).json(formatDataToSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error: "Account was created with Google. Try signing in with Google",
        });
      }
    })
    .catch((err) => {
      console.error("Error signing in user:", err);
      return res.status(500).json({ error: "Failed to sign in user" });
    });
});

// Endpoint for Google authentication
server.post("/google-auth", async (req, res) => {
  try {
    const { access_token } = req.body;

    const decodedUser = await getAuth().verifyIdToken(access_token);
    const { email, name, picture } = decodedUser;

    const modifiedPicture = picture.replace("s96-c", "s384-c");
    let user = await User.findOne({ "personal_info.email": email }).select(
      "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
    );

    if (!user) {
      const username = await generateUsername(email);
      user = new User({
        personal_info: {
          fullname: name,
          email,
          profile_img: modifiedPicture,
          username,
        },
        google_auth: true,
      });

      await user.save();
    } else if (!user.google_auth) {
      return res.status(403).json({
        error:
          "This email was signed up without Google. Please log in with a password to access the account",
      });
    }

    return res.status(200).json(formatDataToSend(user));
  } catch (error) {
    console.error("Error during Google authentication:", error);
    return res.status(500).json({
      error:
        "Failed to authenticate you with Google. Try with another Google account",
    });
  }
});

// Endpoint for changing user password
server.post("/change-password", verifyJWT, (req, res) => {
  let { currentPassword, newPassword } = req.body;

  if (
    !passwordRegex.test(currentPassword) ||
    !passwordRegex.test(newPassword)
  ) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, one lowercase and one uppercase letters",
    });
  }

  User.findOne({ _id: req.user })
    .then((user) => {
      if (user.google_auth) {
        return res.status(403).json({
          error:
            "You can't change account's password because you logged in through Google",
        });
      }

      bcrypt.compare(
        currentPassword,
        user.personal_info.password,
        (err, result) => {
          if (err) {
            console.error("Error changing password:", err);
            return res.status(500).json({
              error:
                "Some error occurred while changing the password, please try again later",
            });
          }

          if (!result) {
            return res
              .status(403)
              .json({ error: "Incorrect current password" });
          }

          if (currentPassword == newPassword) {
            return res.status(403).json({
              error: "New password cannot be the same as current password",
            });
          }

          bcrypt.hash(newPassword, 10, (err, hashed_password) => {
            User.findOneAndUpdate(
              { _id: req.user },
              { "personal_info.password": hashed_password }
            )
              .then(() => {
                return res
                  .status(200)
                  .json({ status: "Password changed successfully!" });
              })
              .catch((err) => {
                console.error("Error saving password:", err);
                return res.status(500).json({
                  error:
                    "Some error occurred while saving new password, please try again later",
                });
              });
          });
        }
      );
    })
    .catch((err) => {
      console.error("Error finding user:", err);
      return res.status(500).json({ status: "User Not Found" });
    });
});

// Endpoint to fetch the latest blogs
server.post("/latest-blogs", (req, res) => {
  let { page } = req.body;

  const maxLimit = 4;

  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.error("Error fetching latest blogs:", err);
      return res.status(500).json({ error: "Failed to fetch latest blogs" });
    });
});

// Endpoint to count all the latest published blogs
server.post("/all-latest-blogs-count", (req, res) => {
  Blog.countDocuments({ draft: false })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.error("Error counting latest blogs:", err);
      return res.status(500).json({ error: "Failed to count latest blogs" });
    });
});

// Endpoint to fetch trending blogs
server.get("/trending-blogs", (req, res) => {
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({
      "activity.total_read": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.error("Error fetching trending blogs:", err);
      return res.status(500).json({ error: "Failed to fetch trending blogs" });
    });
});

// Endpoint to search for blogs
server.post("/search-blogs", (req, res) => {
  let { tag, query, author, page, limit, eliminate_blog } = req.body;

  let findQuery;

  if (tag) {
    findQuery = { tags: tag, draft: false, blog_id: { $ne: eliminate_blog } };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  let maxLimit = limit ? limit : 3;

  Blog.find(findQuery)
    .populate(
      "author",
      "personal_info.profile_img personal_info.username personal_info.fullname -_id"
    )
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.error("Error searching blogs:", err);
      return res.status(500).json({ error: "Failed to search blogs" });
    });
});

// Endpoint to count the total number of blogs
server.post("/search-blogs-count", (req, res) => {
  let { tag, author, query } = req.body;

  let findQuery;

  if (tag) {
    findQuery = { tags: tag, draft: false };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { author, draft: false };
  }

  Blog.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.error("Error counting documents:", err);
      return res.status(500).json({ error: "Failed to count documents" });
    });
});

// Endpoint to search for users
server.post("/search-users", (req, res) => {
  let { query } = req.body;

  User.find({ "personal_info.username": new RegExp(query, "i") })
    .limit(50)
    .select(
      "personal_info.fullname personal_info.username personal_info.profile_img -_id"
    )
    .then((users) => {
      return res.status(200).json({ users });
    })
    .catch((err) => {
      console.error("Error searching users:", err);
      return res.status(500).json({ error: "Failed to search users" });
    });
});

// Endpoint to retrieve user profile
server.post("/get-profile", (req, res) => {
  let { username } = req.body;

  User.findOne({ "personal_info.username": username })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then((user) => {
      return res.status(200).json(user);
    })
    .catch((err) => {
      console.error("Error fetching user profile:", err);
      return res.status(500).json({ error: "Failed to fetch user profile" });
    });
});

// Endpoint to update user profile image
server.post("/update-profile-img", verifyJWT, async (req, res) => {
  let { url } = req.body;

  await User.findOneAndUpdate(
    { _id: req.user },
    { "personal_info.profile_img": url }
  )
    .then(() => {
      return res.status(200).json({ profile_img: url });
    })
    .catch((err) => {
      console.error("Error updating profile image:", err);
      return res.status(500).json({ error: "Failed to update profile image" });
    });
});

// Endpoint to update user profile information
server.post("/update-profile", verifyJWT, async (req, res) => {
  let { username, bio, social_links } = req.body;
  const bioLimit = 150;

  if (username.length < 3) {
    return res
      .status(403)
      .json({ error: "Username should be at least 3 letters long." });
  }

  if (bio.length > bioLimit) {
    return res
      .status(403)
      .json({ error: `Bio should not exceed ${bioLimit} characters.` });
  }

  let socialLinksArr = Object.keys(social_links);

  try {
    for (let i = 0; i < socialLinksArr.length; i++) {
      if (social_links[socialLinksArr[i]].length) {
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if (
          !hostname.includes(`${socialLinksArr[i]}.com`) &&
          socialLinksArr[i] != "website"
        ) {
          return res.status(403).json({
            error: `${socialLinksArr[i]} link is invalid.`,
          });
        }
      }
    }
  } catch (err) {
    return res.status(500).json({
      error: "You must provide full social links with http(s) included",
    });
  }

  let UpdateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links,
  };

  await User.findOneAndUpdate({ _id: req.user }, UpdateObj, {
    runValidators: true,
  })
    .then(() => {
      return res.status(200).json({ username });
    })
    .catch((err) => {
      if (err.code == 11000) {
        return res.status(409).json({ error: "Username is already taken." });
      }

      console.error("Error updating user profile:", err);
      return res.status(500).json({ error: "Failed to update user profile." });
    });
});

// Endpoint to create a new blog post
server.post("/create-blog", verifyJWT, async (req, res) => {
  let authorId = req.user;
  let { title, banner, content, tags, des, draft, id } = req.body;

  if (!title.trim()) {
    return res
      .status(400)
      .json({ error: "Please provide a title for the blog." });
  }

  if (!draft) {
    if (!des.length || !des.length > 200) {
      return res.status(400).json({
        error: "Description must be between 1 and 200 characters long.",
      });
    }

    if (!banner.length) {
      return res
        .status(400)
        .json({ error: "Please provide a banner for the blog." });
    }

    if (!content.blocks.length) {
      return res.status(400).json({ error: "Content cannot be empty!" });
    }

    if (!tags.length || tags.length > 10) {
      return res
        .status(400)
        .json({ error: "Please provide between 1 and 10 tags for the blog." });
    }
  }

  tags = tags.map((tag) => tag.toLowerCase());

  let blog_id =
    id ||
    title
      .replace(/[^a-zA-Z0-9]/g, " ")
      .replace(/\s+/g, "-")
      .trim() + nanoid();

  if (id) {
    await Blog.findOneAndUpdate(
      { blog_id },
      { title, des, banner, content, tags, draft: draft ? draft : false }
    )
      .then(() => {
        return res.status(200).json({ id: blog_id });
      })
      .catch((err) => {
        return res.status(500).json({ error: err.message });
      });
  } else {
    let blog = new Blog({
      title,
      des,
      banner,
      content,
      tags,
      author: authorId,
      blog_id,
      draft: Boolean(draft),
    });

    await blog
      .save()
      .then(async (blog) => {
        let incrementVal = draft ? 0 : 1;

        await User.findOneAndUpdate(
          { _id: authorId },
          {
            $inc: { "account_info.total_posts": incrementVal },
            $push: { blogs: blog._id },
          }
        )
          .then((user) => {
            return res.status(200).json({ id: blog.blog_id });
          })
          .catch((err) => {
            return res
              .status(500)
              .json({ error: "Failed to update total posts number" });
          });
      })
      .catch((err) => {
        console.error("Error creating/updating blog:", err);
        return res.status(500).json({ error: "Failed to create/update blog." });
      });
  }
});

// Endpoint to retrieve a blog post
server.post("/get-blog", async (req, res) => {
  let { blog_id, draft, mode } = req.body;

  let incrementVal = mode != "edit" ? 1 : 0;

  await Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incrementVal } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .select("title banner content tags des activity publishedAt blog_id")
    .then(async (blog) => {
      await User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        { $inc: { "account_info.total_reads": incrementVal } }
      ).catch((err) => {
        return res.status(404).json({ error: "Blog not found" });
      });

      if (blog.draft && !draft) {
        return res.status(500).json({ error: "You cannot access draft blog" });
      }

      return res.status(200).json({ blog });
    })
    .catch((err) => {
      console.error("Error fetching blog:", err);
      return res.status(500).json({ error: "Failed to fetch blog" });
    });
});

// Endpoint to like or dislike a blog post
server.post("/like-blog", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { _id, isLikedByUser } = req.body;

  let incrementVal = isLikedByUser ? -1 : 1;

  await Blog.findOneAndUpdate(
    { _id },
    { $inc: { "activity.total_likes": incrementVal } }
  )
    .then(async (blog) => {
      if (!isLikedByUser) {
        let like = new Notification({
          type: "like",
          blog: _id,
          notification_for: blog.author,
          user: user_id,
        }).catch((err) => {
          return res.status(404).json({ error: "Blog not found" });
        });

        like.save().then(() => {
          return res.status(200).json({ liked_by_user: true });
        });
      } else {
        await Notification.findOneAndDelete({
          user: user_id,
          type: "like",
          blog: _id,
        })
          .then(() => {
            return res.status(200).json({ liked_by_user: false });
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }
    })
    .catch((err) => {
      console.error("Error liking/disliking blog:", err);
      return res.status(500).json({ error: "Failed to like/dislike blog" });
    });
});

// Endpoint to check if a blog post is liked by a user
server.post("/is-liked-by-user", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { _id } = req.body;

  await Notification.exists({ user: user_id, type: "like", blog: _id })
    .then((result) => {
      return res.status(200).json({ result });
    })
    .catch((err) => {
      console.error("Error checking if blog is liked by user:", err);
      return res
        .status(500)
        .json({ error: "Failed to check if blog is liked by user" });
    });
});

// Endpoint to add a comment to a blog post
server.post("/add-comment", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { _id, comment, blog_author, replying_to, notification_id } = req.body;

  if (!comment.length) {
    return res
      .status(403)
      .json({ error: "Write something to leave a comment..." });
  }

  //Creating a comment doc
  let commentObj = {
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
  };

  if (replying_to) {
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }

  await new Comment(commentObj)
    .save()
    .then(async (commentFile) => {
      let { comment, commentedAt, children } = commentFile;

      await Blog.findOneAndUpdate(
        { _id },
        {
          $push: { comments: commentFile._id },
          $inc: {
            "activity.total_comments": 1,
            "activity.total_parent_comments": replying_to ? 0 : 1,
          },
        }
      );

      let notificationObj = {
        type: replying_to ? "reply" : "comment",
        blog: _id,
        notification_for: blog_author,
        user: user_id,
        comment: commentFile._id,
      };

      if (replying_to) {
        notificationObj.replied_on_comment = replying_to;

        await Comment.findOneAndUpdate(
          { _id: replying_to },
          { $push: { children: commentFile._id } }
        ).then((replyingToCommentDoc) => {
          notificationObj.notification_for = replyingToCommentDoc.commented_by;
        });

        if (notification_id) {
          await Notification.findOneAndUpdate(
            { _id: notification_id },
            { reply: commentFile._id }
          );
        }
      }

      await new Notification(notificationObj).save();

      return res.status(200).json({
        comment,
        commentedAt,
        _id: commentFile._id,
        user_id,
        children,
      });
    })
    .catch((err) => {
      console.error("Error adding comment:", err);
      return res.status(500).json({ error: "Failed to add comment" });
    });
});

// Endpoint to retrieve comments for a specific blog post
server.post("/get-blog-comments", async (req, res) => {
  let { blog_id, skip } = req.body;

  let maxLimit = 5;

  await Comment.find({ blog_id, isReply: false })
    .populate(
      "commented_by",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .skip(skip)
    .limit(maxLimit)
    .sort({ commentedAt: -1 })
    .then((comment) => {
      return res.status(200).json(comment);
    })
    .catch((err) => {
      console.error("Error fetching blog comments:", err);
      return res.status(500).json({ error: "Failed to fetch blog comments" });
    });
});

// Endpoint to retrieve replies for a specific comment
server.post("/get-replies", async (req, res) => {
  let { _id, skip } = req.body;

  let maxLimit = 5;

  await Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        limit: maxLimit,
        skip: skip,
        sort: { commentedAt: -1 },
      },
      populate: {
        path: "commented_by",
        select:
          "personal_info.fullname personal_info.username personal_info.profile_img",
      },
      select: "-blog_id -updatedAt",
    })
    .select("children")
    .then((doc) => {
      return res.status(200).json({ replies: doc.children });
    })
    .catch((err) => {
      console.error("Error fetching comment replies:", err);
      return res.status(500).json({ error: "Failed to fetch comment replies" });
    });
});

const deleteComments = async (_id) => {
  await Comment.findOneAndDelete({ _id }).then(async (comment) => {
    if (comment.parent) {
      await Comment.findOneAndUpdate(
        { _id: comment.parent },
        { $pull: { children: _id } }
      );
    }

    await Notification.findOneAndDelete({ comment: _id });

    await Notification.findOneAndUpdate(
      { reply: _id },
      { $unset: { reply: 1 } }
    );

    await Blog.findOneAndUpdate(
      { _id: comment.blog_id },
      {
        $pull: { comments: _id },
        $inc: {
          "activity.total_comments": -1,
          "activity.total_parent_comments": comment.parent ? 0 : -1,
        },
      }
    )
      .then((blog) => {
        if (comment.children.length) {
          comment.children.map((replies) => {
            deleteComments(replies);
          });
        }

        console.log("Comment and associated data deleted successfully");
      })
      .catch((err) => {
        console.error("Error deleting comment:", err.message);
      });
  });
};

// Endpoint to delete a comment
server.post("/delete-comment", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { _id } = req.body;

  await Comment.findOne({ _id })
    .then(async (comment) => {
      if (user_id == comment.commented_by || user_id == comment.blog_author) {
        await deleteComments(_id);

        return res.status(200).json({ status: "Done" });
      } else {
        return res
          .status(403)
          .json({ error: "You cannot delete this comment" });
      }
    })
    .catch((err) => {
      console.error("Error deleting comment:", err.message);
      return res.status(500).json({ error: "Failed to delete the comment" });
    });
});

// Endpoint to check if there are new notifications for a user
server.get("/new-notification", verifyJWT, async (req, res) => {
  let user_id = req.user;

  await Notification.exists({
    notification_for: user_id,
    seen: false,
    user: { $ne: user_id },
  })
    .then((result) => {
      if (result) {
        return res.status(200).json({ new_notification_available: true });
      } else {
        return res.status(200).json({ new_notification_available: false });
      }
    })
    .catch((err) => {
      console.error("Error checking new notifications:", err.message);
      return res
        .status(500)
        .json({ error: "Failed to check new notifications" });
    });
});

// Endpoint to retrieve notifications for a user
server.post("/notifications", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { page, filter, deletedDocCount } = req.body;

  let maxLimit = 10;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };

  let skipDocs = (page - 1) * maxLimit;

  if (filter != "all") {
    findQuery.type = filter;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  await Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .populate(
      "user",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .populate("comment", "comment")
    .populate("replied_on_comment", "comment")
    .populate("reply", "comment")
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply")
    .then(async (notifications) => {
      await Notification.updateMany(findQuery, { seen: true })
        .skip(skipDocs)
        .limit(maxLimit);

      return res.status(200).json({ notifications });
    })
    .catch((err) => {
      console.error("Error fetching notifications:", err.message);
      return res.status(500).json({ error: "Failed to fetch notifications" });
    });
});

// Endpoint to count all notifications for a user
server.post("/all-notifications-count", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { filter } = req.body;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };

  if (filter != "all") {
    findQuery.type = filter;
  }

  await Notification.countDocuments(findQuery)
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.error("Error counting notifications:", err.message);
      return res.status(500).json({ error: "Failed to count notifications" });
    });
});

// Endpoint to retrieve blogs written by a user
server.post("/user-written-blogs", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { page, draft, query, deletedDocCount } = req.body;

  let maxLimit = 4;
  let skipDocs = (page - 1) * maxLimit;

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  await Blog.find({ author: user_id, draft, title: new RegExp(query, "i") })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select(" title banner des publishedAt blog_id activity draft -_id ")
    .then((blogs) => {
      return res.status(200).json({ blogs });
    })
    .catch((err) => {
      console.error("Error retrieving user-written blogs:", err.message);
      return res
        .status(500)
        .json({ error: "Failed to retrieve user-written blogs" });
    });
});

// Endpoint to count all blogs written by a user
server.post("/user-written-blogs-count", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { draft, query } = req.body;

  await Blog.countDocuments({
    author: user_id,
    draft,
    title: new RegExp(query, "i"),
  })
    .then((count) => {
      return res.status(200).json({ totalDocs: count });
    })
    .catch((err) => {
      console.error("Error counting user-written blogs:", err.message);
      return res
        .status(500)
        .json({ error: "Failed to count user-written blogs" });
    });
});

// Endpoint to delete a blog post
server.post("/delete-blog", verifyJWT, async (req, res) => {
  let user_id = req.user;

  let { blog_id } = req.body;

  await Blog.findOneAndDelete({ blog_id })
    .then(async (blog) => {
      await Notification.deleteMany({ blog: blog._id });

      await Comment.deleteMany({ blog_id: blog._id });

      await User.findOneAndUpdate(
        { _id: user_id },
        { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } }
      );

      return res.status(200).json({ status: "Blog deleted successfully" });
    })
    .catch((err) => {
      console.error("Error deleting blog:", err.message);
      return res.status(500).json({ error: "Failed to delete blog" });
    });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
