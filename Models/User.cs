namespace RssReader.Models
{
    public class User
    {
        public string id { get; set; }
        public string email { get; set; }
        public string password { get; set; }
    }

    public class UserInput
    {
        public string email { get; set; }
        public string password { get; set; }
    }
}
