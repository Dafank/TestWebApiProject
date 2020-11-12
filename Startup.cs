using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TestWebApi.UserModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using TestWebApi.Configuration;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using NETCore.MailKit.Infrastructure.Internal;
using NETCore.MailKit.Extensions;

namespace TestWebApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddDbContext<StudentsIdentityDbContext>(options =>
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<StudentUser, IdentityRole>()
                .AddEntityFrameworkStores<StudentsIdentityDbContext>()
                .AddDefaultTokenProviders();

            services.AddMailKit(config => 
            config.UseMailKit(Configuration.GetSection("Email").Get<MailKitOptions>()));
            

            services.AddAuthentication()
                .AddFacebook(option =>
                {
                    option.AppId = "2736713439935288";
                    option.AppSecret = "48c54c19308fb023953566c56aa97a64";
                }
                );

            var jwtSection = Configuration.GetSection("JwtBearerTokenSettings");
            services.Configure<JwtBearerTokenSettings>(jwtSection);
            var jwtBearerTokenSettings = jwtSection.Get<JwtBearerTokenSettings>();
            var key = Encoding.ASCII.GetBytes(jwtBearerTokenSettings.SecretKey);

            services.AddAuthentication(options =>
            {  
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; 
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; 
            })
                .AddJwtBearer(options => 
                { 
                    options.RequireHttpsMetadata = false; 
                    options.SaveToken = true; 
                    options.TokenValidationParameters = new TokenValidationParameters() 
                    { 
                        ValidateIssuer = true, 
                        ValidIssuer = jwtBearerTokenSettings.Issuer, 
                        ValidateAudience = true,
                        ValidAudience = jwtBearerTokenSettings.Audience, 
                        ValidateIssuerSigningKey = true, 
                        IssuerSigningKey = new SymmetricSecurityKey(key), 
                        ValidateLifetime = true, 
                        ClockSkew = TimeSpan.Zero 
                    }; 
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication(); 
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
